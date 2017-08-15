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

public class Scheme {
    private int     port;
    private String  protocol;
    private Boolean encryption;

    public Scheme(String protocol) {
        this.protocol = protocol.toUpperCase();

        switch (this.protocol) {
            case "HTTP":
                this.port = 80;
                this.encryption = false;
                break;

            case "HTTPS":
                this.port = 443;
                this.encryption = true;
                break;

            default:
                this.port = -1;
                this.encryption = false;
                break;
        }
    }

    public int getPort() {
        return this.port;
    }

    public String getProtocol() {
        return this.protocol;
    }

    public Boolean getEncryption() {
        return this.encryption;
    }
}