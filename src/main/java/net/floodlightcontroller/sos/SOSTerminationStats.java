package net.floodlightcontroller.sos;

import java.io.IOException;
import java.util.UUID;

import net.floodlightcontroller.sos.web.SOSTerminationStatsSerializer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * A container to house the information we receive from
 * an agent upon a successful transfer with SOS.
 * @author Ryan Izard, rizard@g.clemson.edu
 *
 */
@JsonSerialize(using=SOSTerminationStatsSerializer.class)
public class SOSTerminationStats implements ISOSTerminationStats {
	private static final Logger log = LoggerFactory.getLogger(SOSTerminationStats.class);

	private UUID transfer_id;
	private int overhead;
	private int avg_sent_bytes;
	private int std_sent_bytes;
	private int avg_chunks;
	private int std_chunks;
	private boolean is_client_side_agent;

	private SOSTerminationStats() { }

	/**
	 * Take a raw JSON string received from an SOS agent and
	 * parse it into an ISOSTerminationStats object. The assumption
	 * of this JSON parser is that the string is a single JSON object
	 * with nothing but key:value pairs within. Only those statistics
	 * keys defined within ISOSTerminationStats (beginning with STR_KEY_*)
	 * will be parsed. 
	 * @param json a valid JSON string
	 * @return
	 */
	public static ISOSTerminationStats parseFromJson(String json) {
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;
		SOSTerminationStats stats = new SOSTerminationStats();

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
				} 
				switch (key) {
				case STR_KEY_CHUNKS_AVG:
					try {
						stats.avg_chunks = Integer.parseInt(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_CHUNKS_AVG, value);
						stats.avg_chunks = 0;
					}
					break;
				case STR_KEY_CHUNKS_STD:
					try {
						stats.std_chunks = Integer.parseInt(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_CHUNKS_STD, value);
						stats.std_chunks = 0;
					}
					break;
				case STR_KEY_OVERHEAD:
					try {
						stats.overhead = Integer.parseInt(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_OVERHEAD, value);
						stats.overhead = 0;
					}
					break;
				case STR_KEY_SENT_BYTES_AVG:
					try {
					stats.avg_sent_bytes = Integer.parseInt(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_SENT_BYTES_AVG, value);
						stats.avg_sent_bytes = 0;
					}
					break;
				case STR_KEY_SENT_BYTES_STD:
					try {
						stats.std_sent_bytes = Integer.parseInt(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_SENT_BYTES_STD, value);
						stats.std_sent_bytes = 0;
					}
					break;
				case STR_KEY_TRANSFER_ID:
					stats.transfer_id = UUID.fromString(value); /* let this exception propagate out */
					break;
				case STR_KEY_TYPE:
					stats.is_client_side_agent = (value.trim().equalsIgnoreCase(STR_VALUE_TYPE_CLIENT) ? true : false);
					break;
				default:
					log.warn("Got unknown termination stats key:value of {}:{}", key, value);
					break;
				}
			}
		} catch (IOException e) {
			log.error("Error parsing JSON into SOSTerminationStats {}", e);
		}

		if (stats.transfer_id == null) {
			log.warn("Could not locate a valid transfer ID in termination stats {}", json);
		}

		return stats;
	}

	@Override
	public UUID getTransferID() {
		return transfer_id;
	}

	@Override
	public int getOverhead() {
		return overhead;
	}

	@Override
	public int getSentBytesAvg() {
		return avg_sent_bytes;
	}

	@Override
	public int getSentBytesStd() {
		return std_sent_bytes;
	}

	@Override
	public int getChunksAvg() {
		return avg_chunks;
	}

	@Override
	public int getChunksStd() {
		return std_chunks;
	}
	
	@Override
	public boolean isClientSideAgent() {
		return is_client_side_agent;
	}
}