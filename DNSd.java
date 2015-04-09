import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class DNSd {
	static Logger log = Logger.getLogger("DNSd");
	int httpPort = 9998, dnsPort = 9999;
	String hostsFile = "hosts.txt";
	String host = "betadata.me";
	byte[] defaultIp = ByteBuffer.allocate(4)
			.putInt(ipToInt("162.243.157.169")).array();
	String controlIp = null;// "12.24.2.2",if not null，only this ip is
	// allowed to control the server
	boolean seted = false;
	static ConcurrentHashMap<Integer, byte[]> resolved = new ConcurrentHashMap<>();

	/**
	 * save resolved to disk(file)
	 */
	private void save() {
		if (seted) {
			try {
				Files.write(Paths.get(hostsFile), dump().getBytes());
				seted = false;
			} catch (IOException e) {
				log.warning(e.getLocalizedMessage());
			}
		}
	}

	/**
	 * memory resolved map to txt
	 * 
	 * @return
	 */
	private String dump() {
		StringBuilder sb = new StringBuilder();
		for (int key : resolved.keySet()) {
			sb.append(intToIp(key)).append("\t")
					.append(bytesToIp(resolved.get(key))).append("\n");
		}
		return sb.toString();
	}

	/**
	 * load hosts files into memory(resolved)
	 */
	private void load() {
		try (Scanner scan = new Scanner(new File(hostsFile));) {
			while (scan.hasNextLine()) {
				String line = scan.nextLine();
				int idx = line.indexOf('\t');
				resolved.put(ipToInt(line.substring(0, idx)),
						ipToBytes(line.substring(idx + 1)));
			}
		} catch (Exception e) {
			log.warning(e.getMessage());
		}
	}

	/**
	 * start a httpserver to control your dns server
	 */
	@SuppressWarnings("restriction")
	private void startHttpServer() {
		try {
			HttpServer server = HttpServer.create(new InetSocketAddress(
					httpPort), 0);
			log.info("http control server started: " + httpPort);

			server.createContext("/", new HttpHandler() {
				@Override
				public void handle(HttpExchange t) {
					try {
						log.info(t.getRemoteAddress() + "\t"
								+ t.getRequestURI());
						String[] req = t.getRequestURI().toString()
								.substring(1).split("/");
						String ret = "error, unkonwn!";

						if (req.length > 0
								&& ((controlIp != null && bytesToIp(
										t.getRemoteAddress().getAddress()
												.getAddress())
										.equals(controlIp)) || controlIp == null)) {
							switch (req[0]) {
							case "save":
								save();
								ret = "saved!";
								break;
							case "set":// set/192.168.0.1[/202.96.204.3]
								// TODO check ip format
								if (req.length == 3) {
									seted = true;
									resolved.put(ipToInt(req[2]),
											ipToBytes(req[1]));
									ret = "seted: " + host + "->" + req[1]
											+ " (on ip " + req[2] + ")";
								} else if (req.length == 2) {
									seted = true;
									resolved.put(bytesToInt(t
											.getRemoteAddress().getAddress()
											.getAddress()), ipToBytes(req[1]));
									ret = "seted: " + host + "->" + req[1]
											+ " (on ip "
											+ t.getRemoteAddress().getAddress()
											+ ")";
								} else
									ret = "seted: failed! check your url: "
											+ t.getRequestURI();
								break;
							default:
								ret = dump();
								break;
							}
						}
						byte[] retBytes = ret.getBytes("UTF-8");
						t.sendResponseHeaders(200, retBytes.length);
						t.getResponseHeaders().add("Content-Type",
								"text/plain; charset=utf-8");
						OutputStream os = t.getResponseBody();
						os.write(retBytes);
						os.close();
					} catch (Exception e) {
						e.printStackTrace();
					} finally {
						t.close();
					}
				}
			});
			server.start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// ip string byte[] converts
	private int ipToInt(String ipAddress) {
		long result = 0;
		String[] ipAddressInArray = ipAddress.split("\\.");
		for (int i = 3; i >= 0; i--) {
			long ip = Long.parseLong(ipAddressInArray[3 - i]);
			result |= ip << (i * 8);
		}
		return (int) result;
	}

	private byte[] ipToBytes(String ip) {
		return ByteBuffer.allocate(4).putInt(ipToInt(ip)).array();
	}

	private String intToIp(int i) {
		return ((i >> 24) & 0xFF) + "." + ((i >> 16) & 0xFF) + "."
				+ ((i >> 8) & 0xFF) + "." + (i & 0xFF);
	}

	private int bytesToInt(byte[] bytes) {
		int val = 0;
		for (int i = 0; i < bytes.length; i++) {
			val <<= 8;
			val |= bytes[i] & 0xff;
		}
		return val;
	}

	private String bytesToIp(byte[] bytes) {
		return ((bytes[0]) & 0xFF) + "." + ((bytes[1]) & 0xFF) + "."
				+ ((bytes[2]) & 0xFF) + "." + (bytes[3] & 0xFF);
	}

	private void startDnsd() {

		try (DatagramSocket serverSocket = new DatagramSocket(dnsPort)) {
			byte[] receiveData = new byte[512];
			log.info("DNSd started at :" + dnsPort);
			while (true) {
				try {

					DatagramPacket receivePacket = new DatagramPacket(
							receiveData, receiveData.length);
					serverSocket.receive(receivePacket);

					StringBuilder qname = new StringBuilder();
					int idx = 12;// skip
									// transaction/id/flags/questions/answer/authority/additional
					int len = receiveData[idx];
					while (len > 0) {
						qname.append(".").append(
								new String(receiveData, idx + 1, len));
						idx += len + 1;
						len = receiveData[idx];
					}
					if (qname.length() > 0) {
						String name = qname.substring(1).toLowerCase();
						int type = receiveData[idx + 1] * 256
								+ receiveData[idx + 2];
						log.info(receivePacket.getAddress() + ":"
								+ receivePacket.getPort() + "\t" + name + "\t"
								+ type);

						if ((!name.equals(host))
								&& (!name.endsWith("." + host))) {
							continue;// keep silence
						}
						if (type != 1 && !name.equals(host)) {
							continue;// we only response for A records, except
										// for MX
										// for host
						}

						ByteArrayOutputStream bo = new ByteArrayOutputStream();
						bo.write(new byte[] { receiveData[0], receiveData[1],
								(byte) 0x81, (byte) 0x80, 0x00, 0x01, 0x00,
								0x01, 0x00, 0x00, 0x00, 0x00 });
						// write query
						byte[] req = Arrays.copyOfRange(receiveData, 12,
								idx + 5);
						bo.write(req);
						bo.write(req);
						bo.write(ByteBuffer.allocate(4)
								.putInt(name.equals(host) ? 3600 : 10).array());// ttl，
						if (type == 1) {
							bo.write(new byte[] { 0x00, 0x04 });
							int val = bytesToInt(receivePacket.getAddress()
									.getAddress());
							bo.write((!name.equals(host))
									&& resolved.containsKey(val) ? resolved
									.get(val) : defaultIp);
						} else {// for MX
							String mx = "mxdomain.qq.com";
							bo.write(ByteBuffer.allocate(2)
									.putShort((short) (mx.length() + 4))
									.array());
							bo.write(0x00);
							bo.write(0x05);// preference
							for (String s : mx.split("\\.")) {
								bo.write((byte) s.length());
								bo.write(s.getBytes());
							}
							bo.write(0x00);
						}

						byte[] sendData = bo.toByteArray();
						DatagramPacket sendPacket = new DatagramPacket(
								sendData, sendData.length,
								receivePacket.getAddress(),
								receivePacket.getPort());
						serverSocket.send(sendPacket);

					}

				} catch (Exception e) {
					log.warning(e.getMessage());
				}
			}
		} catch (Exception e) {
			log.warning(e.getMessage());
		}

	}

	public static void main(String[] args) {
		DNSd dnsd = new DNSd();
		for (String arg : args) {
			if (arg.startsWith("-http")) {
				dnsd.httpPort = Integer.parseInt(arg.substring(5));
			} else if (arg.startsWith("-dns")) {
				dnsd.dnsPort = Integer.parseInt(arg.substring(4));
			} else if (arg.startsWith("-host")) {
				dnsd.host = arg.substring(5);
			} else if (arg.startsWith("-ip")) {
				dnsd.defaultIp = dnsd.ipToBytes(arg.substring(3));
			} else if (arg.startsWith("-cip")) {
				dnsd.controlIp = arg.substring(4);
			}
		}
		System.out.println("i'm go to serve you, master!\n" + dnsd);
		dnsd.load();
		dnsd.startHttpServer();
		// auto save after 10mins
		new Thread() {
			{
				this.setDaemon(true);
			}

			public void run() {
				while (true) {
					try {
						sleep(600000);
						dnsd.save();
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			};
		}.start();
		// auto save when exit
		Runtime.getRuntime().addShutdownHook(new Thread() {
			@Override
			public void run() {
				dnsd.save();
			}
		});
		// i'll block by start dns server
		dnsd.startDnsd();
	}

	// for debug
	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("DNSd:\n -http=").append(httpPort).append("\n -dns=")
				.append(dnsPort).append("\n -host=").append(host)
				.append("\n -ip=").append(bytesToIp(defaultIp))
				.append("\n -cip=").append(controlIp);
		return builder.toString();
	}

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 3];
		StringBuffer sb = new StringBuffer();
		StringBuffer sb1 = new StringBuffer();

		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 3] = hexArray[v >>> 4];
			hexChars[j * 3 + 1] = hexArray[v & 0x0F];
			hexChars[j * 3 + 2] = ' ';
			char c = (char) bytes[j];
			sb.append(" ").append(Character.isLetterOrDigit(c) ? c : '!')
					.append(" ");
			sb1.append(" ").append(j).append(j > 9 ? "" : " ");
		}
		return new String(hexChars) + "\n" + sb + "\n" + sb1;
	}

}
