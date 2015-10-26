package net.floodlightcontroller.sos.web;

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

public class ModuleResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(ModuleResource.class);
	protected static final String STR_OPERATION_ENABLE = "enable";	
	protected static final String STR_OPERATION_DISABLE = "disable";	

	@Get
	public Map<String, String> getModuleMode() {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());

		Map<String, String> ret = new HashMap<String, String>();
		ret.put("enabled", Boolean.toString(sosService.isEnabled()));
		return ret;
	}

	@Put
	@Post
	public Map<String, String> handleModule(String json) {
		ISOSService sosService = (ISOSService) getContext().getAttributes().get(ISOSService.class.getCanonicalName());
		String operation = (String) getRequestAttributes().get("operation");

		Map<String, String> ret = new HashMap<String, String>();

		if (operation.equalsIgnoreCase(STR_OPERATION_ENABLE)) {
			SOSReturnCode rc = sosService.enable();
			switch (rc) {
			case ENABLED:
				ret.put(Code.CODE, Code.OKAY);
				ret.put(Code.MESSAGE, "SOS enabled.");
				break;
			default:
				ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
				ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
				break;
			}
		} else if (operation.equalsIgnoreCase(STR_OPERATION_DISABLE)) {
			SOSReturnCode rc = sosService.disable();
			switch (rc) {
			case DISABLED:
				ret.put(Code.CODE, Code.OKAY);
				ret.put(Code.MESSAGE, "SOS disabled.");
				break;
			default:
				ret.put(Code.CODE, Code.ERR_BAD_ERR_CODE);
				ret.put(Code.MESSAGE, "Error: Unexpected error code " + rc.toString());
				break;
			}
		} else {
			ret.put(Code.CODE, Code.ERR_UNDEF_OPERATION);
			ret.put(Code.MESSAGE, "Error: Undefined operation " + operation);
		}

		return ret;
	}
}

