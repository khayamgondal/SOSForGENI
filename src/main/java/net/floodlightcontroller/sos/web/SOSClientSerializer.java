package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSClient;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSClientSerializer extends JsonSerializer<ISOSClient> {
	
	@Override
	public void serialize(ISOSClient client, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (client == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS client to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeStringField("ip-address", client.getIPAddr().toString());
		jGen.writeStringField("mac-address", client.getMACAddr().toString());
		jGen.writeStringField("tcp-port", client.getTcpPort().toString());
		jGen.writeEndObject();
	}
}