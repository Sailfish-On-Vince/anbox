/*
 * Copyright (C) 2016 Simon Fels <morphis@gravedo.de>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3, as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranties of
 * MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "anbox/android/ip_config_builder.h"
#include "anbox/container/lxc_container.h"
#include "anbox/system_configuration.h"
#include "anbox/logger.h"
#include "anbox/utils.h"

#include <map>
#include <stdexcept>
#include <fstream>
#include <sstream>

#include <boost/filesystem.hpp>
#include <boost/throw_exception.hpp>
#include <boost/algorithm/string.hpp>

#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <unistd.h>

namespace fs = boost::filesystem;

namespace {
constexpr unsigned int unprivileged_uid{100000};
constexpr unsigned int android_system_uid{1000};
constexpr const char *default_container_ip_address{"192.168.250.2"};
constexpr const std::uint32_t default_container_ip_prefix_length{24};
constexpr const char *default_host_ip_address{"192.168.250.1"};
constexpr const char *default_dns_server{"8.8.8.8"};

constexpr int device_major(__dev_t dev) {
  return int(((dev >> 8) & 0xfff) | ((dev >> 32) & (0xfffff000)));
}

constexpr int device_minor(__dev_t dev) {
  return int((dev & 0xff) | ((dev >> 12) & (0xffffff00)));
}
}

namespace anbox {
namespace container {
LxcContainer::LxcContainer(bool privileged,
                           bool rootfs_overlay,
                           const std::string& container_network_address,
                           const std::string &container_network_gateway,
                           const std::vector<std::string> &container_network_dns_servers,
                           const network::Credentials &creds)
    : state_(State::inactive),
      container_(nullptr),
      privileged_(privileged),
      rootfs_overlay_(rootfs_overlay),
      container_network_address_(container_network_address),
      container_network_gateway_(container_network_gateway),
      container_network_dns_servers_(container_network_dns_servers),
      creds_(creds) {
  utils::ensure_paths({
      SystemConfiguration::instance().container_config_dir(),
      SystemConfiguration::instance().container_state_dir(),
      SystemConfiguration::instance().log_dir(),
  });
}

LxcContainer::~LxcContainer() {
  stop();
  if (container_) lxc_container_put(container_);
}

void LxcContainer::setup_id_maps() {
  const auto base_id = unprivileged_uid;
  const auto max_id = 65536;

  set_config_item("lxc.idmap",
                  utils::string_format("u 0 %d %d", base_id, creds_.uid() - 1));
  set_config_item("lxc.idmap",
                  utils::string_format("g 0 %d %d", base_id, creds_.gid() - 1));

  // We need to bind the user id for the one running the client side
  // process as he is the owner of various socket files we bind mount
  // into the container.
  set_config_item("lxc.idmap",
                  utils::string_format("u %d %d 1", creds_.uid(), creds_.uid()));
  set_config_item("lxc.idmap",
                  utils::string_format("g %d %d 1", creds_.gid(), creds_.gid()));

  set_config_item("lxc.idmap",
                  utils::string_format("u %d %d %d", creds_.uid() + 1,
                                       base_id + creds_.uid() + 1,
                                       max_id - creds_.uid() - 1));
  set_config_item("lxc.idmap",
                  utils::string_format("g %d %d %d", creds_.uid() + 1,
                                       base_id + creds_.gid() + 1,
                                       max_id - creds_.gid() - 1));
}

void LxcContainer::setup_network() {
  if (!fs::exists("/sys/class/net/anboxbr0")) {
    WARNING("Anbox bridge interface 'anboxbr0' doesn't exist. Network functionality will not be available");
    return;
  }

  set_config_item("lxc.net.0.type", "veth");
  set_config_item("lxc.net.0.flags", "up");
  set_config_item("lxc.net.0.link", "anboxbr0");

  // Instead of relying on DHCP we will give Android a static IP configuration
  // for the virtual ethernet interface LXC creates for us. This will be bridged
  // to the host and will allows us to have reliable network connectivity and
  // not depend on any other system service.

  android::IpConfigBuilder ip_conf;
  ip_conf.set_version(android::IpConfigBuilder::Version::Version2);
  ip_conf.set_assignment(android::IpConfigBuilder::Assignment::Static);

  std::string address = default_container_ip_address;
  if (!container_network_address_.empty())
    address = container_network_address_;
  ip_conf.set_link_address(address, default_container_ip_prefix_length);

  std::string gateway = default_host_ip_address;
  if (!container_network_gateway_.empty())
    gateway = container_network_gateway_;
  ip_conf.set_gateway(default_host_ip_address);

  if (container_network_dns_servers_.size() > 0)
    ip_conf.set_dns_servers(container_network_dns_servers_);
  else
    ip_conf.set_dns_servers({default_dns_server});

  ip_conf.set_id(0);

  std::vector<std::uint8_t> buffer(512);
  common::BinaryWriter writer(buffer.begin(), buffer.end());
  const auto size = ip_conf.write(writer);

  const auto data_ethernet_path = fs::path("data") / "misc" / "ethernet";
  const auto ip_conf_dir = SystemConfiguration::instance().data_dir() / data_ethernet_path;
  if (!fs::exists(ip_conf_dir))
    fs::create_directories(ip_conf_dir);

  // We have to walk through the created directory hierachy now and
  // ensure the permissions are set correctly. Otherwise the Android
  // system will fail to boot as it isn't allowed to write anything
  // into these directories. As previous versions of Anbox which were
  // published to our users did this incorrectly we need to check on
  // every startup if those directories are still owned by root and
  // if they are we move them over to the unprivileged user.
  auto path = SystemConfiguration::instance().data_dir();
  for (auto iter = data_ethernet_path.begin(); iter != data_ethernet_path.end(); iter++) {
    path /= *iter;

    struct stat st;
    if (stat(path.c_str(), &st) < 0) {
      WARNING("Cannot retrieve permissions of path %s", path);
      continue;
    }

    if (st.st_uid != 0 && st.st_gid != 0)
      continue;

    if (::chown(path.c_str(), unprivileged_uid, unprivileged_uid) < 0)
      WARNING("Failed to set owner for path '%s'", path);
  }

  const auto ip_conf_path = ip_conf_dir / "ipconfig.txt";
  if (fs::exists(ip_conf_path))
    fs::remove(ip_conf_path);

  std::ofstream f(ip_conf_path.string(), std::ofstream::binary);
  if (f.is_open()) {
    f.write(reinterpret_cast<const char*>(buffer.data()), size);
    f.close();
  } else {
    ERROR("Failed to write IP configuration. Network functionality will not be available.");
  }
}

void LxcContainer::start(const Configuration &configuration) {
  if (getuid() != 0)
    BOOST_THROW_EXCEPTION(std::runtime_error("You have to start the container as root"));

  if (container_ && container_->is_running(container_)) {
    WARNING("Container already started, stopping it now");
    container_->stop(container_);
  }

  const auto container_config_dir = SystemConfiguration::instance().container_config_dir();
  if (!container_) {
    DEBUG("Containers are stored in %s", container_config_dir);

    // Remove container config to be be able to rewrite it
    ::unlink(utils::string_format("%s/default/config", container_config_dir).c_str());

    container_ = lxc_container_new("default", container_config_dir.c_str());
    if (!container_)
      BOOST_THROW_EXCEPTION(std::runtime_error("Failed to create LXC container instance"));

    // If container is still running (for example after a crash) we stop it here
    // to ensure
    // its configuration is synchronized.
    if (container_->is_running(container_)) container_->stop(container_);
  }

  // We can mount proc/sys as rw here as we will run the container unprivileged
  // in the end
  set_config_item("lxc.mount.auto", "proc:mixed sys:mixed cgroup:mixed");

  set_config_item("lxc.autodev", "1");
  set_config_item("lxc.pty.max", "1024");
  set_config_item("lxc.tty.max", "0");
  set_config_item("lxc.uts.name", "anbox");

  set_config_item("lxc.group.devices.deny", "");
  set_config_item("lxc.group.devices.allow", "");

  set_config_item("lxc.cgroup.devices.allow", "c 13:* rwm");

  // We can't move bind-mounts, so don't use /dev/lxc/
  set_config_item("lxc.tty.dir", "");

  set_config_item("lxc.environment",
                  "PATH=/system/bin:/system/sbin:/system/xbin");

  set_config_item("lxc.init.cmd", "/anbox-init.sh");

  const auto rootfs_path = SystemConfiguration::instance().rootfs_dir();
  DEBUG("Using rootfs path %s", rootfs_path);
  set_config_item("lxc.rootfs.path", rootfs_path);

  set_config_item("lxc.log.level", "0");
  const auto log_path = SystemConfiguration::instance().log_dir();
  set_config_item("lxc.log.file", utils::string_format("%s/container.log", log_path).c_str());
  set_config_item("lxc.console.logfile", utils::string_format("%s/console.log", log_path).c_str());
  set_config_item("lxc.console.rotate", "1");

  setup_network();

#if ENABLE_SNAP_CONFINEMENT
  // We take the AppArmor profile snapd has defined for us as part of the
  // anbox-support interface. The container manager itself runs within a
  // child profile snap.anbox.container-manager//lxc too.
  set_config_item("lxc.apparmor.profile", "snap.anbox.container-manager//container");
#else
  set_config_item("lxc.apparmor.profile", "unconfined");
#endif

  if (!privileged_)
    setup_id_maps();

  auto bind_mounts = configuration.bind_mounts;

  // Extra bind-mounts for user-namespace setup
  bind_mounts.insert({"/dev/console", "dev/console"});
  bind_mounts.insert({"/dev/full", "dev/full"});
  bind_mounts.insert({"/dev/null", "dev/null"});
  bind_mounts.insert({"/dev/random", "dev/random"});
  bind_mounts.insert({"/dev/tty", "dev/tty"});
  bind_mounts.insert({"/dev/urandom", "dev/urandom"});
  bind_mounts.insert({"/dev/zero", "dev/zero"});

  const auto extra_bind_mounts_file_path = utils::string_format("%s/default/extra_bind_mounts", container_config_dir);
  if(fs::exists(extra_bind_mounts_file_path)) {
    std::string line;
    std::ifstream in(extra_bind_mounts_file_path.c_str());
    if(in.is_open()) {
      while(getline(in, line)) {
        std::vector<std::string> strs;
        boost::split(strs, line, boost::is_any_of(" \t"));
        if(strs.size() == 1 && strs[0] == "") {
        } else if(strs.size() != 2) {
          WARNING("unknown bind mount: %s\n", line.c_str());
        } else if(strs.size() == 2) {
          bind_mounts.insert({strs[0], strs[1]});
        }
      }
    }
  }

  for (const auto &bind_mount : bind_mounts) {
    std::string create_type = "file";

    if (fs::is_directory(bind_mount.first)) create_type = "dir";

    auto target_path = bind_mount.second;
    // The target path needs to be absolute and pointing to the right
    // location inside the target rootfs as otherwise we get problems
    // when running in confined environments like snap's.
    if (!utils::string_starts_with(target_path, "/"))
      target_path = std::string("/") + target_path;
    target_path = rootfs_path + target_path;

    set_config_item(
        "lxc.mount.entry",
        utils::string_format("%s %s none bind,create=%s,optional 0 0",
                             bind_mount.first, target_path, create_type));
  }


  // If we have any additional properties we add them at the top of default.prop
  // within the Android rootfs which we overlay with a bind mount.
  if (configuration.extra_properties.size() > 0) {
    const auto container_state_dir = SystemConfiguration::instance().container_state_dir();
    auto old_default_prop_path = fs::path(rootfs_path) / "default.prop";
    auto new_default_prop_path = fs::path(container_state_dir) / "default.prop";
    auto default_prop_content = utils::read_file_if_exists_or_throw(old_default_prop_path.string());

    std::ofstream default_props;
    default_props.open(new_default_prop_path.string(), std::ios_base::out);
    if (!default_props.is_open())
      throw std::runtime_error("Failed to open new default properties file");

    default_props << "# Properties added by Anbox" << std::endl;
    for (const auto& prop : configuration.extra_properties)
      default_props << prop << std::endl;

    default_props << std::endl
                  << default_prop_content << std::endl;

    default_props.close();

    set_config_item("lxc.mount.entry",
                    utils::string_format("%s %s/default.prop none bind,optional,ro 0 0",
                                         new_default_prop_path.string(), rootfs_path));
  }

  if (!container_->save_config(container_, nullptr))
    BOOST_THROW_EXCEPTION(
        std::runtime_error("Failed to save container configuration"));

  if (not container_->start(container_, 0, nullptr))
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to start container"));

  state_ = Container::State::running;

  DEBUG("Container successfully started");
}

void LxcContainer::stop() {
  if (not container_ || not container_->is_running(container_))
    return;

  if (not container_->stop(container_))
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to stop container"));

  state_ = Container::State::inactive;

  DEBUG("Container successfully stopped");
}

void LxcContainer::set_config_item(const std::string &key,
                                   const std::string &value) {
  if (!container_->set_config_item(container_, key.c_str(), value.c_str()))
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to configure LXC container"));
}

Container::State LxcContainer::state() { return state_; }
}  // namespace container
}  // namespace anbox
