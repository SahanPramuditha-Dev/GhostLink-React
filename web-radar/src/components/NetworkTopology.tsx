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
import type { NodeProps } from 'reactflow'
import 'reactflow/dist/style.css'
import {
  Wifi,
  Router,
  Laptop,
  Smartphone,
  Printer,
  Server,
  Home,
  Globe,
} from 'lucide-react'
import { Box, Tooltip, Typography, keyframes } from '@mui/material'
import { DeviceDetailsModal } from './DeviceDetailsModal'

// Keyframe animations
const pulse = keyframes`
  0% { box-shadow: 0 0 0 0 rgba(0, 245, 255, 0.4); }
  70% { box-shadow: 0 0 0 10px rgba(0, 245, 255, 0); }
  100% { box-shadow: 0 0 0 0 rgba(0, 245, 255, 0); }
`

const float = keyframes`
  0% { transform: translateY(0px); }
  50% { transform: translateY(-5px); }
  100% { transform: translateY(0px); }
`

const glow = keyframes`
  0%, 100% { filter: brightness(1); }
  50% { filter: brightness(1.3); }
`

// Custom node component (moved to top, outside NetworkTopology)
interface CustomNodeData {
  label: string
  type?: string
  deviceType?: string
  ip?: string
  mac?: string
  manufacturer?: string
  openPorts?: number[]
  fullDevice?: any
  onClick?: () => void
}
const CustomNode = ({ data, isConnectable, selected }: NodeProps<CustomNodeData>) => {
  const getIcon = () => {
    switch (data.type) {
      case 'router':
        return <Router size={28} color="#00F5FF" />
      case 'laptop':
        return <Laptop size={28} color="#22C55E" />
      case 'mobile':
        return <Smartphone size={28} color="#A855F7" />
      case 'printer':
        return <Printer size={28} color="#F59E0B" />
      case 'server':
        return <Server size={28} color="#EF4444" />
      case 'iot':
        return <Home size={28} color="#06B6D4" />
      case 'internet':
        return <Globe size={28} color="#FFFFFF" />
      default:
        return <Wifi size={28} color="#64748B" />
    }
  }

  const getColors = () => {
    switch (data.type) {
      case 'router':
        return {
          bg: 'rgba(0, 245, 255, 0.15)',
          border: '#00F5FF',
          shadow: 'rgba(0, 245, 255, 0.6)'
        }
      case 'laptop':
        return {
          bg: 'rgba(34, 197, 94, 0.15)',
          border: '#22C55E',
          shadow: 'rgba(34, 197, 94, 0.6)'
        }
      case 'mobile':
        return {
          bg: 'rgba(168, 85, 247, 0.15)',
          border: '#A855F7',
          shadow: 'rgba(168, 85, 247, 0.6)'
        }
      case 'printer':
        return {
          bg: 'rgba(245, 158, 11, 0.15)',
          border: '#F59E0B',
          shadow: 'rgba(245, 158, 11, 0.6)'
        }
      case 'server':
        return {
          bg: 'rgba(239, 68, 68, 0.15)',
          border: '#EF4444',
          shadow: 'rgba(239, 68, 68, 0.6)'
        }
      case 'iot':
        return {
          bg: 'rgba(6, 182, 212, 0.15)',
          border: '#06B6D4',
          shadow: 'rgba(6, 182, 212, 0.6)'
        }
      case 'internet':
        return {
          bg: 'rgba(255, 255, 255, 0.08)',
          border: 'rgba(255, 255, 255, 0.5)',
          shadow: 'rgba(255, 255, 255, 0.3)'
        }
      default:
        return {
          bg: 'rgba(100, 116, 139, 0.15)',
          border: '#64748B',
          shadow: 'rgba(100, 116, 139, 0.6)'
        }
    }
  }

  const colors = getColors()

  return (
    <Tooltip
      title={
        <Box sx={{ p: 1.5 }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
            {data.label}
          </Typography>
          {data.deviceType && (
            <Typography variant="caption" sx={{ display: 'block', color: '#10B981', fontWeight: 600 }}>
              Type: {data.deviceType}
            </Typography>
          )}
          {data.ip && (
            <Typography variant="caption" sx={{ display: 'block', mt: 0.5 }}>
              IP: {data.ip}
            </Typography>
          )}
          {data.mac && (
            <Typography variant="caption" sx={{ display: 'block', mt: 0.3 }}>
              MAC: {data.mac}
            </Typography>
          )}
          {data.manufacturer && data.manufacturer !== "Unknown" && (
            <Typography variant="caption" sx={{ display: 'block', mt: 0.3, color: '#3B82F6' }}>
              Manufacturer: {data.manufacturer}
            </Typography>
          )}
          {data.openPorts && data.openPorts.length > 0 && (
            <Typography variant="caption" sx={{ display: 'block', mt: 0.3, color: '#F59E0B' }}>
              Open Ports: {data.openPorts.join(', ')}
            </Typography>
          )}
        </Box>
      }
      arrow
      placement="top"
    >
      <Box
        sx={{
          width: 140,
          height: 105,
          borderRadius: '12px',
          backgroundColor: colors.bg,
          border: selected ? `3px solid ${colors.border}` : `2px solid ${colors.border}`,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 0.4,
          padding: 0.6,
          backdropFilter: 'blur(8px)',
          boxShadow: `0 4px 20px ${colors.shadow}`,
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
          animation: `${float} 3s ease-in-out infinite`,
          cursor: 'pointer',
          '&:hover': {
            boxShadow: `0 8px 35px ${colors.shadow}`,
            transform: 'scale(1.08) translateY(-3px)',
            animation: `${pulse} 1.5s infinite, ${glow} 2s ease-in-out infinite`,
            borderWidth: '3px',
          },
        }}
      >
        {data.type !== 'internet' && (
          <Handle
            type="target"
            position={Position.Left}
            isConnectable={isConnectable}
            style={{
              backgroundColor: colors.border,
              width: 10,
              height: 10,
              border: '2px solid #020617',
            }}
          />
        )}
        <Box sx={{ animation: `${glow} 3s ease-in-out infinite` }}>
          {getIcon()}
        </Box>
        <Typography
          variant="caption"
          sx={{
            color: '#E2E8F0',
            fontWeight: 700,
            textAlign: 'center',
            maxWidth: '120px',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontSize: '0.75rem',
          }}
        >
          {data.label}
        </Typography>
        {data.deviceType && (
          <Typography
            variant="caption"
            sx={{
              color: colors.border,
              fontSize: '0.65rem',
              fontWeight: 600,
              textAlign: 'center',
              maxWidth: '120px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              textTransform: 'capitalize',
            }}
          >
            {data.deviceType}
          </Typography>
        )}
        {data.type !== 'router' && (
          <Handle
            type="source"
            position={Position.Right}
            isConnectable={isConnectable}
            style={{
              backgroundColor: colors.border,
              width: 10,
              height: 10,
              border: '2px solid #020617',
            }}
          />
        )}
      </Box>
    </Tooltip>
  )
}

// Define nodeTypes outside the NetworkTopology component (to fix the React Flow warning)
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
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const prevInitialNodesRef = useRef<string>('')
  const prevInitialEdgesRef = useRef<string>('')

  // Generate nodes and edges from device data
  const { initialNodes, initialEdges } = useMemo(() => {
    const generatedNodes: any[] = []
    const generatedEdges: any[] = []

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
      if (type?.includes('mobile') || type?.includes('phone') || type?.includes('tablet')) return 'mobile'
      if (type?.includes('laptop') || type?.includes('computer') || type?.includes('windows') || type?.includes('linux')) return 'laptop'
      if (type?.includes('printer')) return 'printer'
      if (type?.includes('server') || type?.includes('nas')) return 'server'
      if (type?.includes('iot') || type?.includes('smart') || type?.includes('embedded')) return 'iot'
      if (type?.includes('network') || type?.includes('router') || type?.includes('switch')) return 'router'
      return 'laptop'
    }

    // Function to validate IP (frontend filter)
    const isValidDevice = (device: Device) => {
      if (!device.ip) return false
      const ip = device.ip
      
      // Filter out non-device IPs
      if (
        ip.startsWith('224.') || // multicast
        ip.startsWith('239.') || // multicast
        ip.startsWith('127.') || // loopback
        ip.startsWith('169.254.') || // link-local
        ip.endsWith('.0') || // network
        ip.endsWith('.255') || // broadcast
        ip === '0.0.0.0'
      ) {
        return false
      }
      
      // Also filter out known virtual interfaces
      const hostname = (device.hostname || '').toLowerCase()
      if (
        hostname.includes('virtual') || 
        hostname.includes('vmware') || 
        hostname.includes('hyper-v') ||
        hostname.includes('virtualbox')
      ) {
        return false
      }
      
      // Only include devices in the same subnet as the local network
      if (networkInfo?.local_ip) {
        const localIpParts = networkInfo.local_ip.split('.')
        const deviceIpParts = ip.split('.')
        // Check first 3 octets (assuming /24 subnet, which is most common)
        if (localIpParts.length >= 3 && deviceIpParts.length >= 3) {
          if (localIpParts[0] !== deviceIpParts[0] || 
              localIpParts[1] !== deviceIpParts[1] || 
              localIpParts[2] !== deviceIpParts[2]) {
            return false
          }
        }
      }
      
      return true
    }

    // Filter devices first
    const filteredDevices = (devices || []).filter(isValidDevice)

    // Position devices in a grid
    const startX = 450
    const startY = 80
    const gapX = 160
    const gapY = 120
    const devicesPerRow = 3

    filteredDevices.forEach((device, index) => {
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
            deviceType: device.device_type,
            ip: device.ip,
            mac: device.mac,
            manufacturer: device.manufacturer,
            openPorts: device.open_ports,
            fullDevice: device, // Store full device object
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

  // Initialize nodes and edges only when data actually changes
  useEffect(() => {
    const newNodesStr = JSON.stringify(initialNodes)
    const newEdgesStr = JSON.stringify(initialEdges)
    
    if (newNodesStr !== prevInitialNodesRef.current || newEdgesStr !== prevInitialEdgesRef.current) {
      setNodes(initialNodes)
      setEdges(initialEdges)
      prevInitialNodesRef.current = newNodesStr
      prevInitialEdgesRef.current = newEdgesStr
    }
  }, [initialNodes, initialEdges, setNodes, setEdges])

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  )

  const onNodeClick = useCallback(
    (_: any, node: any) => {
      if (node.data.fullDevice) {
        setSelectedDevice(node.data.fullDevice)
      }
    },
    []
  )

  return (
    <>
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
          onNodeClick={onNodeClick}
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
      <DeviceDetailsModal
        open={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        device={selectedDevice}
      />
    </>
  )
}
