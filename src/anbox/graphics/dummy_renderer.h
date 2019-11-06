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

#ifndef ANBOX_GRAPHICS_DUMMY_RENDERER_H_
#define ANBOX_GRAPHICS_DUMMY_RENDERER_H_

#ifdef USE_HEADLESS
#include "anbox/graphics/dummy_renderable.h"
#else
#include "anbox/graphics/emugl/Renderable.h"
#endif

#include "anbox/graphics/renderer.h"
#include <EGL/egl.h>

class Renderer : public anbox::graphics::Renderer {
 public:
  virtual ~Renderer();

  void destroyNativeWindow(EGLNativeWindowType native_window) {}

  bool draw(EGLNativeWindowType native_window,
                    const anbox::graphics::Rect& window_frame,
                    const RenderableList& renderables) { return false; }
};

#endif
