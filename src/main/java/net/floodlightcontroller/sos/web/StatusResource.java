package net.floodlightcontroller.sos.web;

import java.util.HashMap;
import java.util.Map;

import net.floodlightcontroller.sos.ISOSService;

import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatusResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(StatusResource.class);

	@Get
	public Map<String, String> handleModule(String json) {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());
		
		Map<String, String> ret = new HashMap<String, String>();
		
		switch (sosService.ready()) {
		case READY:
			ret.put(Code.CODE, Code.OKAY);
			ret.put(Code.MESSAGE, "Ready to accept a transfer");
			break;
		case NOT_READY:
			ret.put(Code.CODE, Code.ERR_NOT_READY);
			ret.put(Code.MESSAGE, "Not ready to accept a transfer");
			break;
		default:
			ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
			ret.put(Code.MESSAGE, "Received improper SOS error code");
			break;
		}
		return ret;
	}
}