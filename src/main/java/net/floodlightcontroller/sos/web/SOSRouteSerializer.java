package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSRoute;
import net.floodlightcontroller.topology.NodePortTuple;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSRouteSerializer extends JsonSerializer<ISOSRoute> {

	@Override
	public void serialize(ISOSRoute rt, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (rt == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS route to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeObjectField("source-device", rt.getSrcDevice());
		jGen.writeObjectField("destination-device", rt.getDstDevice());
		jGen.writeStringField("route-type", rt.getRouteType().toString());
		jGen.writeArrayFieldStart("route");
		for (NodePortTuple npt : rt.getRoute().getPath()) {
			jGen.writeString(npt.toString());
		}
		jGen.writeEndArray();
		jGen.writeEndObject();
	}
}