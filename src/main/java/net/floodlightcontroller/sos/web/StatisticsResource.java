package net.floodlightcontroller.sos.web;

import java.util.HashMap;
import java.util.Map;

import net.floodlightcontroller.sos.ISOSService;
import net.floodlightcontroller.sos.ISOSStatistics;

import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatisticsResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(StatisticsResource.class);

	@Get
	public ISOSStatistics handleStatistics() {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());
		return sosService.getStatistics();
	}
	
	@Delete
	public Map<String, String> clearStatistics() {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());
		
		Map<String, String> ret = new HashMap<String, String>();
		
		switch (sosService.clearStatistics()) {
		case STATS_CLEARED:
			ret.put(Code.CODE, Code.OKAY);
			ret.put(Code.MESSAGE, "Statistics cleared");
			break;
		default:
			ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
			ret.put(Code.MESSAGE, "Received improper SOS error code");
			break;
		}
		return ret;
	}
}