/**
 * Copyright (C) 2016 Alexandre Teyar
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swurg.model;

import com.google.gson.JsonObject;

public class Definition {
    private String     type;
    private JsonObject properties;

    public Definition(String type, JsonObject properties) {
        this.type = type;
        this.properties = properties;
    }

    public String getType() {
        return this.type;
    }

    public JsonObject getProperties() {
        return this.properties;
    }
}