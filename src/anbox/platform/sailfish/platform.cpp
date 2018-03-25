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

#include "anbox/platform/sailfish/platform.h"
#include "anbox/platform/sdl/audio_sink.h"
#include "anbox/wm/window.h"
#include "anbox/logger.h"
#include <audioresource.h>
#include <glib.h>

static audioresource_t *l_audioresource = NULL;
static int l_audioresource_acquired = 0;

namespace {
class NullWindow : public anbox::wm::Window {
 public:
  NullWindow(const anbox::wm::Task::Id &task,
             const anbox::graphics::Rect &frame,
             const std::string &title)
      : anbox::wm::Window(nullptr, task, frame, title) {}
};
}

void on_audioresource_acquired(audioresource_t *audioresource, bool acquired, void *user_data)
{
  l_audioresource_acquired = acquired;
}

namespace anbox {
namespace platform {
SailfishPlatform::SailfishPlatform() {
  if (SDL_Init(SDL_INIT_AUDIO) < 0) {
    const auto message = utils::string_format("Failed to initialize SDL: %s", SDL_GetError());
    BOOST_THROW_EXCEPTION(std::runtime_error(message));
  }

  l_audioresource = audioresource_init(AUDIO_RESOURCE_MEDIA, on_audioresource_acquired, NULL);
  audioresource_acquire(l_audioresource);

  printf("Waiting for audioresource...\n");
  while (!l_audioresource_acquired) {
    g_main_context_iteration(NULL, false);
  }
}

SailfishPlatform::~SailfishPlatform() {
  audioresource_release(l_audioresource);
  audioresource_free(l_audioresource);
}

std::shared_ptr<wm::Window> SailfishPlatform::create_window(
    const anbox::wm::Task::Id &task, const anbox::graphics::Rect &frame, const std::string &title) {
  return std::make_shared<::NullWindow>(task, frame, title);
}

void SailfishPlatform::set_clipboard_data(const ClipboardData &data) {
  (void)data;
  ERROR("Not implemented");
}

SailfishPlatform::ClipboardData SailfishPlatform::get_clipboard_data() {
  ERROR("Not implemented");
  return ClipboardData{};
}

std::shared_ptr<audio::Sink> SailfishPlatform::create_audio_sink() {
  return std::make_shared<sdl::AudioSink>();
}

std::shared_ptr<audio::Source> SailfishPlatform::create_audio_source() {
  ERROR("Not implemented");
  return nullptr;
}

void SailfishPlatform::set_renderer(const std::shared_ptr<Renderer> &renderer) {
  (void) renderer;
  ERROR("Not implemented");
}

void SailfishPlatform::set_window_manager(const std::shared_ptr<wm::Manager> &window_manager) {
  (void) window_manager;
  ERROR("Not implemented");
}

bool SailfishPlatform::supports_multi_window() const {
  return false;
}
}  // namespace wm
}  // namespace anbox
