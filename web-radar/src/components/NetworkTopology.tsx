import { useCallback, useMemo, useRef, useState, useEffect } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
} from 'reactflow'
import 'reactflow/dist/style.css'
import {
  Wifi,
  Router,
  Laptop,
  Smartphone,
  Printer,
  Server,
  Home,
  ShieldAlert,
  Lock,
  Globe,
} from 'lucide-react'
import { Box, Tooltip, Typography } from '@mui/material'

// Custom node component
const CustomNode = ({ data, isConnectable }) => {
  const getIcon = () => {
    switch (data.type) {
      case 'router':
        return <Router size={24} color="#00F5FF" />
      case 'laptop':
        return <Laptop size={24} color="#22C55E" />
      case 'mobile':
        return <Smartphone size={24} color="#A855F7" />
      case 'printer':
        return <Printer size={24} color="#F59E0B" />
      case 'server':
        return <Server size={24} color="#EF4444" />
      case 'iot':
        return <Home size={24} color="#06B6D4" />
      case 'internet':
        return <Globe size={24} color="#FFFFFF" />
      default:
        return <Wifi size={24} color="#64748B" />
    }
  }

  const getBgColor = () => {
    switch (data.type) {
      case 'router':
        return 'rgba(0, 245, 255, 0.1)'
      case 'laptop':
        return 'rgba(34, 197, 94, 0.1)'
      case 'mobile':
        return 'rgba(168, 85, 247, 0.1)'
      case 'printer':
        return 'rgba(245, 158, 11, 0.1)'
      case 'server':
        return 'rgba(239, 68, 68, 0.1)'
      case 'iot':
        return 'rgba(6, 182, 212, 0.1)'
      case 'internet':
        return 'rgba(255, 255, 255, 0.05)'
      default:
        return 'rgba(100, 116, 139, 0.1)'
    }
  }

  const getBorderColor = () => {
    switch (data.type) {
      case 'router':
        return 'rgba(0, 245, 255, 0.6)'
      case 'laptop':
        return 'rgba(34, 197, 94, 0.6)'
      case 'mobile':
        return 'rgba(168, 85, 247, 0.6)'
      case 'printer':
        return 'rgba(245, 158, 11, 0.6)'
      case 'server':
        return 'rgba(239, 68, 68, 0.6)'
      case 'iot':
        return 'rgba(6, 182, 212, 0.6)'
      case 'internet':
        return 'rgba(255, 255, 255, 0.2)'
      default:
        return 'rgba(100, 116, 139, 0.6)'
    }
  }

  return (
    <Tooltip
      title={
        <Box sx={{ p: 1 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
            {data.label}
          </Typography>
          {data.ip && (
            <Typography variant="caption" sx={{ display: 'block' }}>
              IP: {data.ip}
            </Typography>
          )}
          {data.mac && (
            <Typography variant="caption" sx={{ display: 'block' }}>
              MAC: {data.mac}
            </Typography>
          )}
          {data.openPorts && data.openPorts.length > 0 && (
            <Typography variant="caption" sx={{ display: 'block', color: '#F59E0B' }}>
              Open Ports: {data.openPorts.length}
            </Typography>
          )}
        </Box>
      }
      arrow
    >
      <Box
        sx={{
          width: 120,
          height: 80,
          borderRadius: 2,
          backgroundColor: getBgColor(),
          border: `2px solid ${getBorderColor()}`,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 0.5,
          boxShadow: '0 0 15px rgba(0, 0, 0, 0.3)',
          transition: 'all 0.3s ease',
          '&:hover': {
            boxShadow: `0 0 25px ${getBorderColor()}`,
            transform: 'scale(1.05)',
          },
        }}
      >
        {data.type !== 'internet' && (
          <Handle
            type="target"
            position={Position.Left}
            isConnectable={isConnectable}
            style={{ backgroundColor: '#00F5FF', width: 8, height: 8 }}
          />
        )}
        {getIcon()}
        <Typography
          variant="caption"
          sx={{
            color: '#E2E8F0',
            fontWeight: 600,
            textAlign: 'center',
            maxWidth: '100px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {data.label}
        </Typography>
        {data.type !== 'router' && (
          <Handle
            type="source"
            position={Position.Right}
            isConnectable={isConnectable}
            style={{ backgroundColor: '#00F5FF', width: 8, height: 8 }}
          />
        )}
      </Box>
    </Tooltip>
  )
}

const nodeTypes = {
  custom: CustomNode,
}

interface Device {
  ip: string
  mac: string
  hostname: string
  manufacturer: string
  open_ports: number[]
  services: Record<number, string>
  os_guess: string
  device_type: string
  scan_time: string
}

interface NetworkTopologyProps {
  devices?: Device[]
  networkInfo?: {
    local_ip?: string
    gateway?: string
    subnet_mask?: string
    cidr_prefix?: number
    network_cidr?: string
  }
}

export const NetworkTopology = ({ devices = [], networkInfo }: NetworkTopologyProps) => {
  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [reactFlowInstance, setReactFlowInstance] = useState<any>(null)

  // Generate nodes and edges from device data
  const { initialNodes, initialEdges } = useMemo(() => {
    const generatedNodes: any[] = []
    const generatedEdges: any[] = []
    const idCounter = { current: 1 }

    // Add internet node
    generatedNodes.push({
      id: 'internet',
      type: 'custom',
      position: { x: 50, y: 200 },
      data: { label: 'Internet', type: 'internet' },
    })

    // Add router node (gateway)
    const routerId = 'router'
    generatedNodes.push({
      id: routerId,
      type: 'custom',
      position: { x: 250, y: 200 },
      data: {
        label: 'Router',
        type: 'router',
        ip: networkInfo?.gateway || '192.168.1.1',
      },
    })

    // Connect internet to router
    generatedEdges.push({
      id: 'e-internet-router',
      source: 'internet',
      target: routerId,
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: '#00F5FF' },
      style: { stroke: '#00F5FF', strokeWidth: 2 },
    })

    // Determine device types
    const getDeviceType = (device: Device) => {
      const type = device.device_type?.toLowerCase()
      if (type?.includes('mobile') || type?.includes('phone')) return 'mobile'
      if (type?.includes('laptop') || type?.includes('computer') || type?.includes('windows')) return 'laptop'
      if (type?.includes('printer')) return 'printer'
      if (type?.includes('server') || type?.includes('nas')) return 'server'
      if (type?.includes('iot') || type?.includes('smart')) return 'iot'
      return 'laptop'
    }

    // Position devices in a grid
    const startX = 450
    const startY = 80
    const gapX = 160
    const gapY = 120
    const devicesPerRow = 3

    devices.forEach((device, index) => {
      const deviceId = `device-${index}`
      const row = Math.floor(index / devicesPerRow)
      const col = index % devicesPerRow
      const x = startX + col * gapX
      const y = startY + row * gapY

      generatedNodes.push({
        id: deviceId,
        type: 'custom',
        position: { x, y },
        data: {
          label: device.hostname || device.ip,
          type: getDeviceType(device),
          ip: device.ip,
          mac: device.mac,
          openPorts: device.open_ports,
        },
      })

      // Connect device to router
      generatedEdges.push({
        id: `e-router-${deviceId}`,
        source: routerId,
        target: deviceId,
        animated: true,
        markerEnd: { type: MarkerType.ArrowClosed, color: '#00F5FF' },
        style: { stroke: '#00F5FF', strokeWidth: 1.5 },
      })
    })

    return { initialNodes: generatedNodes, initialEdges: generatedEdges }
  }, [devices, networkInfo])

  // Initialize nodes and edges when data changes
  useEffect(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
  }, [initialNodes, initialEdges, setNodes, setEdges])

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  )

  return (
    <Box
      ref={reactFlowWrapper}
      sx={{
        width: '100%',
        height: '100%',
        minHeight: '400px',
        borderRadius: 2,
        overflow: 'hidden',
        border: '1px solid rgba(0, 245, 255, 0.2)',
      }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onInit={setReactFlowInstance}
        nodeTypes={nodeTypes}
        fitView
        style={{ backgroundColor: '#020617' }}
      >
        <Background color="#1E293B" gap={30} />
        <Controls
          style={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(0, 245, 255, 0.3)',
            borderRadius: 2,
          }}
        />
        <MiniMap
          style={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(0, 245, 255, 0.3)',
            borderRadius: 2,
          }}
        />
      </ReactFlow>
    </Box>
  )
}

export default NetworkTopology
