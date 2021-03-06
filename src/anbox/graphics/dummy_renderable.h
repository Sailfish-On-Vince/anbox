/*
* Copyright (C) 2016 Simon Fels <morphis@gravedo.de>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef ANBOX_GRAPHICS_DUMMY_RENDERABLE_H_
#define ANBOX_GRAPHICS_DUMMY_RENDERABLE_H_

#include "anbox/graphics/rect.h"

#include <string>
#include <vector>

#include <cstdint>

class Renderable {
 public:
  Renderable(const std::string &name, const std::uint32_t &buffer,
             const anbox::graphics::Rect &screen_position,
             const anbox::graphics::Rect &crop = {}, const float &alpha = 1.0f);
  ~Renderable();

  std::string name() const;
  std::uint32_t buffer() const;
  anbox::graphics::Rect screen_position() const;
  anbox::graphics::Rect crop() const;
  float alpha() const;

  void set_screen_position(const anbox::graphics::Rect &screen_position);

  inline bool operator==(const Renderable &rhs) const {
    return (name_ == rhs.name() && buffer_ == rhs.buffer() &&
            screen_position_ == rhs.screen_position() && crop_ == rhs.crop() &&
            alpha_ == rhs.alpha());
  }

  inline bool operator!=(const Renderable &rhs) const {
    return !operator==(rhs);
  }

 private:
  std::string name_;
  std::uint32_t buffer_;
  anbox::graphics::Rect screen_position_;
  anbox::graphics::Rect crop_;
  float alpha_;
};

std::ostream &operator<<(std::ostream &out, const Renderable &r);

typedef std::vector<Renderable> RenderableList;

#endif
