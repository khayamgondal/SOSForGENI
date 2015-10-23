package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.SOSWhitelistEntry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSWhitelistEntrySerializer extends JsonSerializer<SOSWhitelistEntry> {

	@Override
	public void serialize(SOSWhitelistEntry entry, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (entry == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS whitelist entry to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeStringField("server-ip-address", entry.getServerIP().toString());
		jGen.writeStringField("client-ip-address", entry.getClientIP().toString());
		jGen.writeStringField("server-tcp-port", entry.getServerPort().toString());
		jGen.writeEndObject();
	}
}