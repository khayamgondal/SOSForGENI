package net.floodlightcontroller.sos.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import net.floodlightcontroller.sos.ISOSService;
import net.floodlightcontroller.sos.ISOSService.SOSReturnCode;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class ConfigResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(ConfigResource.class);
	protected static final String STR_SETTING_PARALLEL = "parallel-connections";	
	protected static final String STR_SETTING_BUFFER_SIZE = "buffer-size";	
	protected static final String STR_SETTING_QUEUE_CAPACITY = "queue-capacity";		
	protected static final String STR_SETTING_HARD_TIMEOUT = "hard-timeout";
	protected static final String STR_SETTING_IDLE_TIMEOUT = "idle-timeout";

	protected static final String STR_INVALID_KEY = "invalid-key";
	protected static final String STR_INVALID_VALUE = "invalid-value";

	@Get
	public Map<String, String> getConfiguration() {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());

		Map<String, String> ret = new HashMap<String, String>();		
		ret.put(STR_SETTING_PARALLEL, Integer.toString(sosService.getNumParallelConnections(), 10));
		ret.put(STR_SETTING_BUFFER_SIZE, Integer.toString(sosService.getBufferSize(), 10));
		ret.put(STR_SETTING_QUEUE_CAPACITY, Integer.toString(sosService.getQueueCapacity(), 10));
		ret.put(STR_SETTING_HARD_TIMEOUT, Integer.toString(sosService.getFlowHardTimeout(), 10));
		ret.put(STR_SETTING_IDLE_TIMEOUT, Integer.toString(sosService.getFlowIdleTimeout(), 10));
		return ret;
	}

	@Put
	@Post
	public Map<String, String> handleConfig(String json) {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());

		Map<String, String> ret = new HashMap<String, String>();

		Map<String, Object> config = parseConfigFromJson(json);

		for (String key : config.keySet()) {
			SOSReturnCode rc;
			switch (key) {
			case STR_SETTING_BUFFER_SIZE:
				rc = sosService.setBufferSize(((Integer) config.get(key)).intValue());
				switch (rc) {
				case CONFIG_SET:
					ret.put(Code.CODE, Code.OKAY);
					ret.put(Code.MESSAGE, "Buffer size set to " + ((Integer) config.get(key)).intValue());
					break;
				default:
					ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
					ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
					break;
				}
				break;
			case STR_SETTING_PARALLEL:
				rc = sosService.setNumParallelConnections(((Integer) config.get(key)).intValue());
				switch (rc) {
				case CONFIG_SET:
					ret.put(Code.CODE, Code.OKAY);
					ret.put(Code.MESSAGE, "Parallel connections set to " + ((Integer) config.get(key)).intValue());
					break;
				default:
					ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
					ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
					break;
				}
				break;
			case STR_SETTING_QUEUE_CAPACITY:
				rc = sosService.setQueueCapacity(((Integer) config.get(key)).intValue());
				switch (rc) {
				case CONFIG_SET:
					ret.put(Code.CODE, Code.OKAY);
					ret.put(Code.MESSAGE, "Queue capacity set to " + ((Integer) config.get(key)).intValue());
					break;
				default:
					ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
					ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
					break;
				}
				break;
			case STR_SETTING_HARD_TIMEOUT:
				rc = sosService.setFlowTimeouts(((Integer) config.get(key)).intValue(), -1);
				switch (rc) {
				case CONFIG_SET:
					ret.put(Code.CODE, Code.OKAY);
					ret.put(Code.MESSAGE, "(Ignored) Hard timeout set to " + ((Integer) config.get(key)).intValue());
					break;
				default:
					ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
					ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
					break;
				}
				break;
			case STR_SETTING_IDLE_TIMEOUT:
				rc = sosService.setFlowTimeouts(-1, ((Integer) config.get(key)).intValue());
				switch (rc) {
				case CONFIG_SET:
					ret.put(Code.CODE, Code.OKAY);
					ret.put(Code.MESSAGE, "Idle timeout set to " + ((Integer) config.get(key)).intValue());
					break;
				default:
					ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
					ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
					break;
				}
				break;
			case STR_INVALID_KEY:
			case STR_INVALID_VALUE:
				ret.put(key, (String) config.get(key));
				break;
			}		
		}

		return ret;
	}

	/**
	 * Expect JSON (any of):
	 * {
	 * 		"parallel-connections"	:	"number",
	 * 		"buffer-size"			:	"bytes",
	 * 		"queue-capacity"		:	"bytes",
	 * 		"idle-timeout"			:	"seconds",
	 * 		"hard-timeout"			:	"seconds"
	 * }
	 * 
	 * @param json
	 * @return
	 */
	private static Map<String, Object> parseConfigFromJson(String json) {
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;

		if (json == null || json.isEmpty()) {
			return null;
		}

		Map<String, Object> ret = new HashMap<String, Object>();

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
				} 
				switch (key) {
				case STR_SETTING_PARALLEL:
					try {
						ret.put(STR_SETTING_PARALLEL, Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid parallel connections {}", value);
						ret.put(STR_INVALID_VALUE, "Invalid value '" + value + "' for key '" + key + "'");
					}
					break;
				case STR_SETTING_BUFFER_SIZE:
					try {
						ret.put(STR_SETTING_BUFFER_SIZE, Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid buffer size {}", value);
						ret.put(STR_INVALID_VALUE, "Invalid value '" + value + "' for key '" + key + "'");
					}
					break;
				case STR_SETTING_QUEUE_CAPACITY:
					try {
						ret.put(STR_SETTING_QUEUE_CAPACITY, Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid queue capacity {}", value);
						ret.put(STR_INVALID_VALUE, "Invalid value '" + value + "' for key '" + key + "'");
					}
					break;
				case STR_SETTING_IDLE_TIMEOUT:
					try {
						ret.put(STR_SETTING_IDLE_TIMEOUT, Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid idle timeout {}", value);
						ret.put(STR_INVALID_VALUE, "Invalid value '" + value + "' for key '" + key + "'");
					}
					break;
				case STR_SETTING_HARD_TIMEOUT:
					try {
						ret.put(STR_SETTING_HARD_TIMEOUT, Integer.parseInt(value));
					} catch (IllegalArgumentException e) {
						log.error("Invalid hard timeout {}", value);
						ret.put(STR_INVALID_VALUE, "Invalid value '" + value + "' for key '" + key + "'");
					}
					break;
				default:
					log.warn("Received invalid key {} parsing SOS config", key);
					ret.put(STR_INVALID_KEY, "Invalid key '" + key + "'");
					break;
				}
			}
		} catch (IOException e) {
			log.error("Error parsing JSON config {}", e);
		}
		return ret;
	}
}