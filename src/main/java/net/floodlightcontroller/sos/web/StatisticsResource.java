package net.floodlightcontroller.sos.web;

import net.floodlightcontroller.sos.ISOSService;
import net.floodlightcontroller.sos.ISOSStatistics;

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
}