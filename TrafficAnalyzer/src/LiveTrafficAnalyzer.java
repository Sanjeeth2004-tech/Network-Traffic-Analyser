import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.data.category.DefaultCategoryDataset;

public class LiveTrafficAnalyzer {

    private final List<Map<String, Object>> packets = new ArrayList<>();
    private boolean running = false;

    public void processPacket(Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            String proto = "Other";
            if (packet.contains(TcpPacket.class))
                proto = "TCP";
            else if (packet.contains(UdpPacket.class))
                proto = "UDP";

            Map<String, Object> data = new HashMap<>();
            data.put("src", ip.getHeader().getSrcAddr().getHostAddress());
            data.put("dst", ip.getHeader().getDstAddr().getHostAddress());
            data.put("proto", proto);
            data.put("len", packet.length());
            data.put("timestamp", System.currentTimeMillis());

            synchronized (packets) {
                packets.add(data);
            }
        }
    }

    public void startSniffing(int durationSec) throws PcapNativeException, NotOpenException {
        packets.clear();
        running = true;
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        for (int i = 0; i < allDevs.size(); i++) {
            System.out.println(i + ": " + allDevs.get(i).getName() + " - " + allDevs.get(i).getDescription());
        }
        PcapNetworkInterface nif = allDevs.get(3); // replace 0 with the correct index

        // PcapNetworkInterface nif = Pcaps.findAllDevs().get(0); // pick first
        // interface
        int snapLen = 65536;
        int timeout = 50;
        PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        pool.submit(() -> {
            try {
                // Cast lambda to PacketListener to avoid ambiguity
                handle.loop(-1, (PacketListener) packet -> processPacket(packet));
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                e.printStackTrace();
            }
        });

        try {
            Thread.sleep(durationSec * 1000L); // sniff duration
        } catch (InterruptedException ignored) {
        }

        handle.breakLoop();
        handle.close();
        running = false;
        pool.shutdownNow();
    }

    public List<String> analyzePackets() {
        List<String> alerts = new ArrayList<>();
        if (packets.isEmpty()) {
            alerts.add("⚠️ No packets captured. Try again.");
            return alerts;
        }

        Map<String, Long> ipCounts = packets.stream()
                .collect(Collectors.groupingBy(p -> (String) p.get("src"), Collectors.counting()));

        for (Map.Entry<String, Long> entry : ipCounts.entrySet()) {
            if (entry.getValue() > 10) {
                alerts.add("🚨 [ALERT] High traffic from " + entry.getKey() + ": " + entry.getValue() + " packets");
            }
        }

        if (alerts.isEmpty()) {
            alerts.add("✅ No threats detected.");
        }
        return alerts;
    }

    public void showProtocolChart() {
        if (packets.isEmpty())
            return;

        Map<String, Long> protoCounts = packets.stream()
                .collect(Collectors.groupingBy(p -> (String) p.get("proto"), Collectors.counting()));

        DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        for (Map.Entry<String, Long> e : protoCounts.entrySet()) {
            dataset.addValue(e.getValue(), "Protocols", e.getKey());
        }

        var chart = ChartFactory.createBarChart(
                "Protocol Distribution", "Protocol", "Packet Count", dataset);
        ChartFrame frame = new ChartFrame("Protocol Chart", chart);
        frame.setSize(600, 400);
        frame.setVisible(true);
    }

    // GUI
    public static class App extends JFrame {
        private final JTextArea textArea;
        private final JLabel statusLabel;
        private final JLabel counterLabel;
        private final JButton startBtn;
        private final JButton chartBtn;
        private final LiveTrafficAnalyzer analyzer = new LiveTrafficAnalyzer();

        public App() {
            setTitle("🔍 Real-Time Network Traffic Analyzer");
            setSize(800, 700);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLayout(new BorderLayout());

            JPanel panel = new JPanel();
            panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            panel.setBackground(new Color(30, 30, 47));

            JLabel projectName = new JLabel("🛡️ ZKP Warriors");
            projectName.setFont(new Font("Segoe UI", Font.BOLD, 20));
            projectName.setForeground(new Color(0, 212, 255));
            projectName.setAlignmentX(Component.CENTER_ALIGNMENT);

            JLabel title = new JLabel("🛰️ Real-Time Network Traffic Analyzer");
            title.setFont(new Font("Segoe UI", Font.BOLD, 16));
            title.setForeground(Color.WHITE);
            title.setAlignmentX(Component.CENTER_ALIGNMENT);

            JLabel description = new JLabel("<html>📡 This tool captures live network packets for 15 seconds.<br>"
                    + "It analyzes abnormal behavior (too many packets from the same IP).<br>"
                    + "You can also view a protocol usage chart.</html>");
            description.setForeground(Color.LIGHT_GRAY);
            description.setAlignmentX(Component.CENTER_ALIGNMENT);

            statusLabel = new JLabel("Status: 🟡 Idle");
            statusLabel.setForeground(Color.WHITE);
            counterLabel = new JLabel("Packets Captured: 0");
            counterLabel.setForeground(Color.WHITE);

            startBtn = new JButton("▶️ Start Sniffing");
            chartBtn = new JButton("📊 Show Protocol Chart");
            chartBtn.setEnabled(false);

            textArea = new JTextArea(18, 90);
            textArea.setBackground(new Color(46, 46, 63));
            textArea.setForeground(Color.WHITE);
            textArea.setFont(new Font("Consolas", Font.PLAIN, 12));
            textArea.setEditable(false);

            JScrollPane scroll = new JScrollPane(textArea);

            startBtn.addActionListener(e -> startSniffing());
            chartBtn.addActionListener(e -> analyzer.showProtocolChart());

            panel.add(projectName);
            panel.add(title);
            panel.add(description);
            panel.add(statusLabel);
            panel.add(counterLabel);
            panel.add(startBtn);
            panel.add(chartBtn);
            panel.add(scroll);

            add(panel, BorderLayout.CENTER);
        }

        private void startSniffing() {
            textArea.setText("");
            statusLabel.setText("Status: 🟠 Sniffing...");
            counterLabel.setText("Packets Captured: 0");
            startBtn.setEnabled(false);
            chartBtn.setEnabled(false);

            new Thread(() -> {
                try {
                    analyzer.startSniffing(15);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                List<String> alerts = analyzer.analyzePackets();
                SwingUtilities.invokeLater(() -> {
                    textArea.setText(String.join("\n", alerts));
                    statusLabel.setText("Status: 🟢 Done");
                    counterLabel.setText("Packets Captured: " + analyzer.packets.size());
                    startBtn.setEnabled(true);
                    chartBtn.setEnabled(true);
                });
            }).start();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new App().setVisible(true));
    }
}
