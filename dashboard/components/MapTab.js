// OT Network Topology Map Component
function RenderMapTab({ alerts, simActive }) {
  const canvasRef = React.useRef(null);
  
  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let animationFrameId;
    let packetProgress = 0;

    const getStatusColor = (status) => {
      if (status === 'Critical' || status === 'High') return '#f43f5e'; // Red
      if (status === 'Medium') return '#fb923c'; // Orange
      if (status === 'Low') return '#3b82f6'; // Blue
      return '#00b4d8'; // Cyan (Clean)
    };

    const getMaximumSeverity = (ip, descFilter = null) => {
      const nodeAlerts = alerts.filter(a => {
        const matchesIp = a.source_ip === ip || a.destination_ip === ip;
        if (!matchesIp) return false;
        if (descFilter) {
          const desc = (a.description || '').toLowerCase();
          const det = (a.detector || '').toLowerCase();
          const matchesFilter = desc.includes(descFilter) || det.includes(descFilter);
          if (!matchesFilter) return false;
        }
        return true;
      });
      if (nodeAlerts.length === 0) return 'Clean';
      
      let hasCritical = nodeAlerts.some(a => window.normalizeSeverity(a.severity) === 'Critical');
      if (hasCritical) return 'Critical';
      let hasHigh = nodeAlerts.some(a => window.normalizeSeverity(a.severity) === 'High');
      if (hasHigh) return 'High';
      let hasMedium = nodeAlerts.some(a => window.normalizeSeverity(a.severity) === 'Medium');
      if (hasMedium) return 'Medium';
      return 'Low';
    };

    function drawTopology() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Node coordinates and dynamic state
      const nodes = {
        hmi: { 
          x: 150, 
          y: 200, 
          label: "SCADA HMI (10.0.0.1)", 
          role: "Master", 
          status: getMaximumSeverity("10.0.0.1")
        },
        plc: { 
          x: 550, 
          y: 120, 
          label: "Water Pump PLC (10.0.0.2)", 
          role: "Slave", 
          status: getMaximumSeverity("10.0.0.2", "pump")
        },
        rtu: { 
          x: 550, 
          y: 280, 
          label: "Telemetry RTU (10.0.0.2)", 
          role: "Slave", 
          status: getMaximumSeverity("10.0.0.2", "psi")
        },
        workstation: { 
          x: 350, 
          y: 80, 
          label: "Eng Workstation (10.0.0.11)", 
          role: "Operator", 
          status: getMaximumSeverity("10.0.0.11")
        }
      };

      // Draw connections
      ctx.lineWidth = 1.5;
      
      // HMI to PLC
      ctx.strokeStyle = '#22252f';
      ctx.beginPath();
      ctx.moveTo(nodes.hmi.x, nodes.hmi.y);
      ctx.lineTo(nodes.plc.x, nodes.plc.y);
      ctx.stroke();

      // HMI to RTU
      ctx.beginPath();
      ctx.moveTo(nodes.hmi.x, nodes.hmi.y);
      ctx.lineTo(nodes.rtu.x, nodes.rtu.y);
      ctx.stroke();

      // Workstation to HMI
      ctx.beginPath();
      ctx.moveTo(nodes.workstation.x, nodes.workstation.y);
      ctx.lineTo(nodes.hmi.x, nodes.hmi.y);
      ctx.stroke();

      // Animated packets along all active communication paths
      packetProgress += 0.008;
      if (packetProgress > 1) packetProgress = 0;

      const links = [
        { from: nodes.workstation, to: nodes.hmi, isThreat: nodes.workstation.status !== 'Clean' },
        { from: nodes.hmi, to: nodes.plc, isThreat: nodes.hmi.status !== 'Clean' || nodes.plc.status !== 'Clean' },
        { from: nodes.hmi, to: nodes.rtu, isThreat: nodes.hmi.status !== 'Clean' || nodes.rtu.status !== 'Clean' }
      ];

      links.forEach(link => {
        const pX = link.from.x + (link.to.x - link.from.x) * packetProgress;
        const pY = link.from.y + (link.to.y - link.from.y) * packetProgress;
        
        ctx.fillStyle = link.isThreat ? '#f43f5e' : '#00b4d8';
        ctx.beginPath();
        ctx.arc(pX, pY, 4, 0, Math.PI * 2);
        ctx.fill();
      });

      // Draw Nodes
      Object.entries(nodes).forEach(([key, node]) => {
        const isAlerting = node.status !== 'Clean' && node.status !== 'Low';
        const color = getStatusColor(node.status);

        if (isAlerting) {
          ctx.shadowBlur = 15;
          ctx.shadowColor = color;
          ctx.fillStyle = color + '22'; // Flashing alpha glow
          ctx.beginPath();
          ctx.arc(node.x, node.y, 24, 0, Math.PI * 2);
          ctx.fill();
        }

        ctx.shadowBlur = 0;
        ctx.fillStyle = '#11131a';
        ctx.strokeStyle = isAlerting ? color : '#22252f';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 16, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 6, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = '#e2e4ea';
        ctx.font = 'bold 10px Inter';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y - 24);
        
        ctx.fillStyle = '#7c8293';
        ctx.font = '9px JetBrains Mono';
        ctx.fillText(`[${node.role}]`, node.x, node.y + 28);
      });

      animationFrameId = requestAnimationFrame(drawTopology);
    }

    drawTopology();
    return () => cancelAnimationFrame(animationFrameId);
  }, [alerts, simActive]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white">OT Network Topology Map</h2>
        <p className="text-xs text-siemMuted">Visual mapping of SCADA master polling and RTU/PLC slave response paths</p>
      </div>

      <div className="bg-siemCard border border-siemBorder rounded p-5 flex justify-center items-center shadow-lg">
        <canvas ref={canvasRef} width="700" height="400" className="bg-slate-950/50 rounded border border-siemBorder max-w-full"></canvas>
      </div>
    </div>
  );
}

// Bind to window for global availability
window.RenderMapTab = RenderMapTab;
