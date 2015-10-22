package net.floodlightcontroller.sos;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.sos.web.SOSRouteSerializer;

@JsonSerialize(using=SOSRouteSerializer.class)
public interface ISOSRoute {
	
	public ISOSDevice getSrcDevice();
	
	public ISOSDevice getDstDevice();
	
	public SOSRouteType getRouteType();
	
	public Route getRoute();
}
