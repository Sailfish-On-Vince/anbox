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

#include "anbox/container/lxc_container.h"
#include "anbox/system_configuration.h"
#include "anbox/logger.h"
#include "anbox/utils.h"

#include <map>
#include <stdexcept>
#include <fstream>

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
constexpr unsigned int unprivileged_user_id{100000};
}

namespace anbox {
namespace container {
LxcContainer::LxcContainer(bool privileged, const network::Credentials &creds)
    : state_(State::inactive), container_(nullptr),  privileged_(privileged), creds_(creds) {
  utils::ensure_paths({
      SystemConfiguration::instance().container_config_dir(),
      SystemConfiguration::instance().log_dir(),
  });
}

LxcContainer::~LxcContainer() {
  stop();
  if (container_) lxc_container_put(container_);
}

void LxcContainer::setup_id_maps() {
  const auto base_id = unprivileged_user_id;
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

  if (fs::exists("/sys/class/net/anboxbr0")) {
    set_config_item("lxc.net.0.type", "veth");
    set_config_item("lxc.net.0.flags", "up");
    set_config_item("lxc.net.0.link", "anboxbr0");
  }

#if 0
    // Android uses namespaces as well so we have to allow nested namespaces for LXC
    // which are otherwise forbidden by AppArmor.
    set_config_item("lxc.apparmor.profile", "anbox-container");

    const auto seccomp_profile_path = fs::path(utils::get_env_value("SNAP", "/etc/anbox")) / "seccomp" / "anbox.sc";
    set_config_item("lxc.seccomp.profile", seccomp_profile_path.string().c_str());
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
