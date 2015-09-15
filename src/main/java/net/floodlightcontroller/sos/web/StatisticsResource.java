package net.floodlightcontroller.sos.web;

import java.util.Map;

import net.floodlightcontroller.sos.ISOSService;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatisticsResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(StatisticsResource.class);

	@Get
	public Map<String, String> handleAgent(String json) {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());

		String param = (String) getRequestAttributes().get("operation");
		return null;
	}
}

