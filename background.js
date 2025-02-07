chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
      // Build a payload with basic details.
      // In practice, you would need to capture the flow details (packet counts, lengths, etc.)
      const urlObj = new URL(details.url);
      const payload = {
        src_ip: details.initiator || "",  // This may be empty; you might need another way to obtain the source IP.
        destination_port: urlObj.port ? parseInt(urlObj.port) : 80,
        total_fwd_packets: 10,           // Placeholder value
        total_backward_packets: 10,      // Placeholder value
        total_length_of_fwd_packets: 500,  // Placeholder value
        total_length_of_bwd_packets: 500,  // Placeholder value
        syn_flag_count: 1,               // Placeholder value
        ack_flag_count: 1,               // Placeholder value
        fin_flag_count: 0,               // Placeholder value
        fwd_packet_length: 50,           // Placeholder value
        fwd_packet_length_max: 100,      // Placeholder value
        bwd_packet_length_max: 100,      // Placeholder value
        flow_duration: 0.5,              // Placeholder value (in seconds)
        init_win_bytes_forward: 14600,   // Placeholder value
        flow_packets: 20,                // Placeholder value
        down_up_ratio: 1.0               // Placeholder value
      };
  
      // Send the payload to your Flask firewall server.
      fetch("http://your-firewall-server-address:5000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      })
      .then(response => response.json())
      .then(data => {
        if (data.action === "block") {
          console.log("Blocking request to:", details.url);
          // Note: The chrome.webRequest API requires a synchronous response for blocking.
          // Asynchronous fetch here is only for demonstration. In practice,
          // you might pre-fetch decisions or use the declarativeNetRequest API.
        } else {
          console.log("Allowing request to:", details.url);
        }
      })
      .catch(err => console.error("Firewall server error:", err));
  
      // Return empty object; note that you cannot cancel the request asynchronously.
      return {};
    },
    {urls: ["<all_urls>"]},
    ["blocking"]
  );
  