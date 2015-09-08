package net.floodlightcontroller.sos.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.floodlightcontroller.sos.ISOSService;
import net.floodlightcontroller.sos.SOSAgent;
import net.floodlightcontroller.sos.ISOSService.SOSReturnCode;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class AgentResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(AgentResource.class);
	protected static final String STR_OPERATION_ADD = "add";	
	protected static final String STR_OPERATION_REMOVE = "remove";

	protected static final String STR_IP = "ip-address";
	protected static final String STR_DATA_PORT = "data-port";
	protected static final String STR_CONTROL_PORT = "control-port";

	@Get("json")
	public Map<String, String> handleAgent(String json) {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());
		String operation = ((String) getRequestAttributes().get(SOSWebRoutable.STR_OPERATION)).toLowerCase().trim();
		
		Map<String, String> ret = new HashMap<String, String>();

		SOSAgent agent = parseAgentFromJson(json);
		if (agent == null) {
			ret.put("code", "1");
			ret.put("message", "Error: Could not parse JSON.");
		} else if (operation.equals(STR_OPERATION_ADD)) {
			SOSReturnCode rc = sosService.addAgent(agent);
			switch (rc) {
			case AGENT_ADDED:
				ret.put("code", "0");
				ret.put("message", "Agent successfully added. It will be available for the next SOS session.");
				break;
			case ERR_DUPLICATE_AGENT:
				ret.put("code", "2");
				ret.put("message", "Error: A duplicate agent was detected. Unable to add agent to SOS.");
				break;
			default:
				ret.put("code", "3");
				ret.put("message", "Error: Unexpected error code " + rc.toString() + ". Agent was not added.");
			}
		} else if (operation.equals(STR_OPERATION_REMOVE)) {
			SOSReturnCode rc = sosService.removeAgent(agent);
			switch (rc) {
			case AGENT_REMOVED:
				ret.put("code", "0");
				ret.put("message", "Agent successfully removed. It will be no longer be available for the next SOS session.");
				break;
			case ERR_UNKNOWN_AGENT:
				ret.put("code", "2");
				ret.put("message", "Error: The agent specified was not found. Unable to remove agent from SOS.");
				break;
			default:
				ret.put("code", "3");
				ret.put("message", "Error: Unexpected error code " + rc.toString() + ". Agent was not removed.");
			}
		}

		return ret;
	}

	private static SOSAgent parseAgentFromJson(String json) {
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;

		IPv4Address ip = IPv4Address.NONE;
		TransportPort dataPort = TransportPort.NONE;
		TransportPort controlPort = TransportPort.NONE;

		if (json == null || json.isEmpty()) {
			return null;
		}

		try {
			try {
				jp = f.createParser(json);
			} catch (JsonParseException e) {
				throw new IOException(e);
			}

			jp.nextToken();
			if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
				throw new IOException("Expected START_OBJECT");
			}

			while (jp.nextToken() != JsonToken.END_OBJECT) {
				if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
					throw new IOException("Expected FIELD_NAME");
				}

				String key = jp.getCurrentName().toLowerCase().trim();
				jp.nextToken();
				String value = jp.getText().toLowerCase().trim();
				if (value.isEmpty() || key.isEmpty()) {
					continue;
				} else if (key.equals(STR_IP)) {
					try {
						ip = IPv4Address.of(value);
					} catch (IllegalArgumentException e) {
						log.error("Invalid IPv4 address {}", value);
					}
				} else if (key.equals(STR_DATA_PORT)) {
					try {
						dataPort = TransportPort.of(Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid data port {}", value);
					}
				} else if (key.equals(STR_CONTROL_PORT)) {
					try {
						controlPort = TransportPort.of(Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid control port {}", value);
					}
				}
			}
		} catch (IOException e) {
			log.error("Error parsing JSON into SOSAgent {}", e);
		}
		
		if (!ip.equals(IPv4Address.NONE) && !dataPort.equals(TransportPort.NONE) && !controlPort.equals(TransportPort.NONE)) {
			return new SOSAgent(ip, dataPort, controlPort);
		} else {
			return null;
		}
	}
}

