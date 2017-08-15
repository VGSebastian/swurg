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

package swurg.utils;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import swurg.model.*;

import java.util.List;
import java.util.Map;

public class Parser {
    public String parseParams(List<Parameter> params) {
        String result = "";

        if (params != null && !params.isEmpty()) {
            StringBuilder stringBuilder = new StringBuilder();

            for (Parameter param : params) {
                stringBuilder.append(param.getName()).append(", ");
            }

            result = stringBuilder.substring(0, stringBuilder.length() - 2);
        }

        return result;
    }

    public String parseInPathParams(String URL, List<Parameter> params) {
        if (params != null && !params.isEmpty()) {
            for (Parameter param : params) {
                if (param.getIn().equals("path")) {
                    URL = URL.replace(param.getName(), param.getName() + "=" + param.getType());
                }
            }
        }

        return URL;
    }

    public String parseInQueryParams(List<Parameter> params) {
        String result = "";

        if (params != null && !params.isEmpty()) {
            StringBuilder stringBuilder = new StringBuilder("?");

            for (Parameter param : params) {
                if (param.getIn().equals("query")) {
                    stringBuilder.append(param.getName()).append("={").append(param.getType()).append("}&");
                }
            }

            result = stringBuilder.substring(0, stringBuilder.length() - 1);
        }

        return result;
    }

    public String parseInBodyParams(List<Parameter> params, JsonObject definitions) {
        Gson   gson   = new Gson();
        String result = "";

        if (params != null && !params.isEmpty()) {
            StringBuilder stringBuilder = new StringBuilder();

            for (Parameter param : params) {
                if (param.getIn().equals("body")) {
                    Schema schema = gson.fromJson(param.getSchema(), Schema.class);
                    String ref    = schema.getRef();

                    stringBuilder.append(parseSchemaParams(ref, definitions));
                }
            }

            if (!stringBuilder.toString().equals("")) {
                result = stringBuilder.substring(0, stringBuilder.length() - 1);
            }
        }

        return result;
    }

    private String parseSchemaParams(String ref, JsonObject definitions) {
        Gson          gson          = new Gson();
        String        result        = "";
        StringBuilder stringBuilder = new StringBuilder();

        try {
            for (Map.Entry<String, JsonElement> entry : definitions.entrySet()) {
                if (ref.contains(entry.getKey())) {
                    Definition definition = gson.fromJson(entry.getValue(), Definition.class);

                    for (Map.Entry<String, JsonElement> entry1 : definition.getProperties().entrySet()) {
                        Property property = gson.fromJson(entry1.getValue(), Property.class);

                        if (property.getRef() != null) {
                            stringBuilder.append(parseSchemaParams(property.getRef(), definitions));
                        } else if (property.getType() != null) {
                            stringBuilder.append(entry1.getKey()).append("={").append(property.getType()).append("}&");
                        } else {
                            stringBuilder.append(entry1.getKey()).append("={ERROR}&");
                        }
                    }
                }
            }
        } catch (Exception ex) {
            // Check the 'definitions' section syntax of the Swagger file input
        }

        result = stringBuilder.toString();

        return result;
    }

    public HTTPRequest BurpHTTPRequest(String HTTPMethod, String URL, String host, int port, Boolean encryption, List<Parameter> params,
                                       JsonObject definitions, List<String> consumes, List<String> produces) {

        Parser parser = new Parser();
        String request;

        if (consumes != null && produces != null) {
            request = HTTPMethod + " " + parser.parseInPathParams(URL, params) + parser.parseInQueryParams(params) + " HTTP/1.1" + "\n"
                      + "Host: " + host + "\n"
                      + "Accept: " + String.join(", ", produces) + "\n"
                      + "Content-Type: " + String.join(", ", consumes)
                      + "\n\n"
                      + parser.parseInBodyParams(params, definitions);
        } else if (consumes != null) {
            request = HTTPMethod + " " + parser.parseInPathParams(URL, params) + parser.parseInQueryParams(params) + " HTTP/1.1" + "\n"
                      + "Host: " + host + "\n"
                      + "Content-Type: " + String.join(", ", consumes)
                      + "\n\n"
                      + parser.parseInBodyParams(params, definitions);
        } else if (produces != null) {
            request = HTTPMethod + " " + parser.parseInPathParams(URL, params) + parser.parseInQueryParams(params) + " HTTP/1.1" + "\n"
                      + "Host: " + host + "\n"
                      + "Accept: " + String.join(", ", produces)
                      + "\n\n"
                      + parser.parseInBodyParams(params, definitions);
        } else {
            request = HTTPMethod + " " + parser.parseInPathParams(URL, params) + parser.parseInQueryParams(params) + " HTTP/1.1" + "\n"
                      + "Host: " + host
                      + "\n\n"
                      + parser.parseInBodyParams(params, definitions);
        }

        return new HTTPRequest(host, port, encryption, request.getBytes());
    }
}
