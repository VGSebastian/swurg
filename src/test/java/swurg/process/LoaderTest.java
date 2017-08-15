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

package swurg.process;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import junit.framework.TestCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swurg.model.Parameter;
import swurg.model.Path;
import swurg.model.REST;
import swurg.utils.Parser;

import java.io.File;
import java.util.List;
import java.util.Map;

public class LoaderTest extends TestCase {
    private Logger logger = LoggerFactory.getLogger("LoaderTest");

    public void testProcess() throws Exception {
        Gson   gson   = new Gson();
        Loader loader = new Loader();
        Parser parser = new Parser();
        REST   API    = loader.process(new File("src/test/resources/testApi.json"));

        assertNotNull("Processed object is null", API);

        List<String> schemes = API.getSchemes();

        logger.info("-------------------------");
        logger.info("<Schemes......>");
        for (String scheme : schemes) {
            logger.info(scheme);
        }

        assertNotNull("'schemes' object is null", schemes);

        String       basePath    = API.getBasePath();
        List<String> consumes    = API.getConsumes();
        List<String> produces    = API.getProduces();
        JsonObject   definitions = API.getDefinitions();

        for (Map.Entry<String, JsonElement> path : API.getPaths().entrySet()) {
            String endpoint = path.getKey();
            String URL      = basePath + endpoint;

            logger.info("-------------------------");
            logger.info("<Endpoint.....>");
            logger.info(endpoint);

            for (Map.Entry<String, JsonElement> entry : path.getValue().getAsJsonObject().entrySet()) {
                logger.info("-------------------------");
                logger.info("<HTTP Method.....>");
                logger.info(entry.getKey().toUpperCase());

                Path call = gson.fromJson(entry.getValue(), Path.class);

                logger.info("<Consumes.....>");
                if (call.getConsumes() != null) {
                    consumes = call.getConsumes();
                }

                if (consumes != null) {
                    logger.info(String.join(", ", consumes));
                } else {
                    logger.info("null");
                }

                logger.info("<Produces.....>");
                if (call.getProduces() != null) {
                    produces = call.getProduces();
                }

                if (consumes != null) {
                    logger.info(String.join(", ", produces));
                } else {
                    logger.info("null");
                }

                List<Parameter> params = call.getParameters();

                logger.info("<Parameters.....>");
                if (params != null && !params.isEmpty()) {
                    logger.info("<In Path.....>");
                    logger.info(parser.parseInPathParams(URL, params));

                    logger.info("<In Query.....>");
                    logger.info(parser.parseInQueryParams(params));

                    logger.info("<In Body.....>");
                    logger.info(parser.parseInBodyParams(params, definitions));
                } else {
                    logger.info("null");
                }
            }
        }
    }
}
