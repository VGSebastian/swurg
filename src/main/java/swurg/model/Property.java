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

public class Property {
    private String type;
    private String format;
    private String description;
    private String $ref;

    public Property(String type, String format, String description, String $ref) {
        this.type = type;
        this.format = format;
        this.description = description;
        this.$ref = $ref;
    }

    public String getType() {
        return this.type;
    }

    public String getFormat() {
        return this.format;
    }

    public String getDescription() {
        return this.description;
    }

    public String getRef() {
        return this.$ref;
    }
}
