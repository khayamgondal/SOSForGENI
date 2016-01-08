package net.floodlightcontroller.sos;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import net.floodlightcontroller.sos.web.SOSTransferStatsSerializer;

import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

/**
 * A container to house the periodic information we receive from
 * an agent during a transfer with SOS.
 * @author Ryan Izard, rizard@g.clemson.edu
 *
 */
@JsonSerialize(using=SOSTransferStatsSerializer.class)
public class SOSTransferStats implements ISOSTransferStats {
	private static final Logger log = LoggerFactory.getLogger(SOSTransferStats.class);

	private UUID transfer_id;
	private boolean is_client_side_agent;
	private Date timestamp;
	private ThroughputTuple throughput_aggregate;
	private Map<Integer, ThroughputTuple> throughput_per_socket;

	private SOSTransferStats() { 
		timestamp = new Date();
		throughput_per_socket = new HashMap<Integer, ThroughputTuple>();
	}

	/**
	 * Take a raw JSON string received from an SOS agent and
	 * parse it into an ISOSTransferStats object. The assumption
	 * of this JSON parser is that the string is a single JSON object
	 * with nothing but key:value pairs within. Only those statistics
	 * keys defined within ISOSTransferStats (beginning with STR_KEY_*)
	 * will be parsed. 
	 * 
	 * 	{
	 * 		"transfer_id"			:	"<UUID>",
	 * 		"agent_type"			:	"<string>",	// client | agent
	 * 		"collection_time"		:	"<long>",   // timestamp in milliseconds (optional; controller will stamp if not present)
	 * 		"cumulative_throughput"	:	"<long>",	// aggregate
	 * 		"rolling_throughput"	:	"<long>",	// aggregate
	 * 		"per_socket_throughput"	:	[			// per-socket throughput (optional; more detailed info if present)
	 * 			{ 
	 * 				"socket_id"				"	"<int>",
	 * 				"cumulative_throughput"	:	"<long>", 
	 * 				"rolling_throughput"	:	"<long>"
	 * 			},
	 * 			{ 
	 * 				"socket_id"				"	"<int>",
	 * 				"cumulative_throughput"	:	"<long>", 
	 * 				"rolling_throughput"	:	"<long>"
	 * 			},
	 * 			...
	 * 			...
	 * 		]
	 * 	}
	 * 
	 * @param json a valid JSON string
	 * @return
	 */
	public static ISOSTransferStats parseFromJson(String json) {
		MappingJsonFactory f = new MappingJsonFactory();
		JsonParser jp;
		SOSTransferStats stats = new SOSTransferStats();

		long agg_cum_tput_tmp = -1;
		long agg_roll_tput_tmp = -1;

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
				String value = "<empty>";

				switch (key) {
				case STR_KEY_CUMULATIVE_THROUGHPUT:
					value = jp.getText().toLowerCase().trim();
					try {
						agg_cum_tput_tmp = Long.parseLong(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_CUMULATIVE_THROUGHPUT, value);
						agg_cum_tput_tmp = 0;
					}
					break;
				case STR_KEY_ROLLING_THROUGHPUT:
					value = jp.getText().toLowerCase().trim();
					try {
						agg_roll_tput_tmp = Long.parseLong(value);
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_ROLLING_THROUGHPUT, value);
						agg_roll_tput_tmp = 0;
					}
					break;
				case STR_KEY_TRANSFER_ID:
					value = jp.getText().toLowerCase().trim();
					stats.transfer_id = UUID.fromString(value); /* let this exception propagate out */
					break;
				case STR_KEY_COLLECTION_TIME:
					value = jp.getText().toLowerCase().trim();
					try {
						stats.timestamp = new Date(Long.parseLong(value));
					} catch (NumberFormatException e) {
						log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_COLLECTION_TIME, value);
						/* default already set to current system time */
					}
					break;
				case STR_KEY_TYPE:
					value = jp.getText().toLowerCase().trim();
					stats.is_client_side_agent = (value.equalsIgnoreCase(STR_VALUE_TYPE_CLIENT) ? true : false);
					break;
				case STR_KEY_PER_SOCKET_THROUGHPUT:
					/* step through array of objects */
					if (jp.getCurrentToken() == JsonToken.START_ARRAY) {
						while (jp.nextToken() != JsonToken.END_ARRAY) {
							if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
								throw new IOException("Expected START_OBJECT");
							}
							
							int socket_id = -1;
							long sock_cum_tput_tmp = -1;
							long sock_roll_tput_tmp = -1;
							while (jp.nextToken() != JsonToken.END_OBJECT) {
								key = jp.getCurrentName().toLowerCase().trim();
								jp.nextToken();
								value = jp.getText().toLowerCase().trim();
								switch (key) {
								case (STR_KEY_SOCKET_ID):
									try {
										socket_id = Integer.parseInt(value);
									} catch (NumberFormatException e) {
										log.error("Could not parse '{}' of '{}'. Using default of -1.", STR_KEY_SOCKET_ID, value);
									}
									break;
								case (STR_KEY_CUMULATIVE_THROUGHPUT):
									try {
										sock_cum_tput_tmp = Long.parseLong(value);
									} catch (NumberFormatException e) {
										log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_CUMULATIVE_THROUGHPUT, value);
										sock_cum_tput_tmp = 0;
									}
									break;
								case (STR_KEY_ROLLING_THROUGHPUT):
									try {
										sock_roll_tput_tmp = Long.parseLong(value);
									} catch (NumberFormatException e) {
										log.error("Could not parse '{}' of '{}'. Using default of 0.", STR_KEY_ROLLING_THROUGHPUT, value);
										sock_roll_tput_tmp = 0;
									}
									break;
								default:
									log.warn("Got unknown transfer (periodic) per-socket stats key:value of {}:{}", key, value);
									break;
								}
							}
							if (socket_id == -1 || sock_cum_tput_tmp == -1 || sock_roll_tput_tmp == -1) {
								log.error("Ignoring per-socket throughput due to missing data. Got socket_id {}, cumulative t-put {}, rolling t-put {}. (-1 --> missing)", new Object[] { socket_id, sock_cum_tput_tmp, sock_roll_tput_tmp });
							} else {
								stats.throughput_per_socket.put(socket_id, ThroughputTuple.of(U64.of(sock_cum_tput_tmp), U64.of(sock_roll_tput_tmp)));
							}
						}
					} else {
						throw new IOException("Expected START_ARRAY");
					}
					break;
				default:
					log.warn("Got unknown transfer (periodic) stats key:value of {}:{}", key, value);
					break;
				}
			}
			if (agg_cum_tput_tmp == -1 || agg_roll_tput_tmp == -1) {
				log.error("Ignoring cumulative t-put {}, rolling t-put {}. (-1 --> missing). Using 0bps as throughputs", agg_cum_tput_tmp, agg_roll_tput_tmp);
				stats.throughput_aggregate = ThroughputTuple.of(U64.of(0), U64.of(0));
			} else {
				stats.throughput_aggregate = ThroughputTuple.of(U64.of(agg_cum_tput_tmp), U64.of(agg_roll_tput_tmp));
			}
		} catch (IOException e) {
			log.error("Error parsing JSON into SOSTransferStats {}", e);
		}

		stats.throughput_aggregate = ThroughputTuple.of(U64.of(agg_cum_tput_tmp), U64.of(agg_roll_tput_tmp));

		if (stats.transfer_id == null) {
			log.warn("Could not locate a valid transfer ID in termination stats {}", json);
		}
		
		return stats;
	}

	@Override
	public U64 getAggregateCumulativeThroughput() {
		return throughput_aggregate.getCumulativeThroughput();
	}

	@Override
	public U64 getAggregateRollingThroughput() {
		return throughput_aggregate.getRollingThroughput();
	}

	@Override
	public U64 getCumulativeThroughput(int socket) {
		return throughput_per_socket.get(socket) != null ? throughput_per_socket.get(socket).getCumulativeThroughput() : U64.ZERO;
	}

	@Override
	public U64 getRollingThroughput(int socket) {
		return throughput_per_socket.get(socket) != null ? throughput_per_socket.get(socket).getRollingThroughput() : U64.ZERO;
	}

	@Override
	public Map<Integer, ThroughputTuple> getAllSocketsThroughput() {
		return Collections.unmodifiableMap(throughput_per_socket);
	}

	@Override
	public long getCollectionTime() {
		return timestamp.getTime();
	}

	@Override
	public UUID getTransferID() {
		return transfer_id;
	}
	
	@Override
	public boolean isClientSideAgent() {
		return is_client_side_agent;
	}
	
	/**
	 * Add data to the existing stats object.
	 * @param moreStats
	 */
	public void appendStats(ISOSTransferStats moreStats) {
		if (this.timestamp.getTime() != moreStats.getCollectionTime()) {
			throw new IllegalArgumentException("Should not update an ISOSTransferStats that is not from the same capture time.");
		}
		if (!this.getTransferID().equals(moreStats.getTransferID())) {
			throw new IllegalArgumentException("Should not update an ISOSTransferStats that is not from the same transfer ID.");
		}
		if (this.isClientSideAgent() != moreStats.isClientSideAgent()) {
			throw new IllegalArgumentException("Should not update an ISOSTransferStats that are not from the same agent.");
		}
		
		if (!moreStats.getAggregateCumulativeThroughput().equals(U64.ZERO) || !moreStats.getAggregateRollingThroughput().equals(U64.ZERO)) {
			this.throughput_aggregate = ThroughputTuple.of(moreStats.getAggregateCumulativeThroughput(), moreStats.getAggregateRollingThroughput());
		}
		
		this.throughput_per_socket.putAll(moreStats.getAllSocketsThroughput());
	}
}