package net.floodlightcontroller.sos.web;

import net.floodlightcontroller.restserver.RestletRoutable;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

public class SOSWebRoutable implements RestletRoutable {
	protected static final String STR_OPERATION = "operation";	
		
    /**
     * Create the Restlet router and bind to the proper resources.
     * These are the operations that can be performed via the
     * REST API. The *Resource classes are responsible for handling
     * the appropriate HTTP commands and parsing any data in the
     * request itself of in the payload (if put or post).
     */
    @Override
    public Restlet getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/agent/{" + STR_OPERATION + "}/json", AgentResource.class);
        router.attach("/whitelist/{" + STR_OPERATION + "}/json", WhitelistResource.class);
        router.attach("/module/{" + STR_OPERATION + "}/json", ModuleResource.class);
        router.attach("/config/json", ConfigResource.class);
        router.attach("/stats/json", StatisticsResource.class);
        return router;
    }

    /**
     * Set the base path for SOS REST API requests.
     * All requests must start with the string
     * indicated here. This string is appended with
     * one of the specific paths above.
     */
    @Override
    public String basePath() {
        return "/wm/sos";
    }
}