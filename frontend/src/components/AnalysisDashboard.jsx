import React from "react";
import { Card, Table, Tag, Alert, Row, Col, Tabs, Progress, List, Collapse, Empty } from "antd";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { useAnalysis } from "../services/AnalysisContext";


const COLORS = [
  "#0088FE", // Azul
  "#00C49F", // Verde
  "#FFBB28", // Amarillo
  "#FF8042", // Naranja
  "#A020F0", // Púrpura
  "#FF6347", // Rojo Tomate
  "#7C4DFF", // Azul Violeta
  "#00CFFF", // Aqua
  "#FF6F61", // Coral
  "#4B9CD3"  // Azul Claro
];

const { TabPane } = Tabs;



const AnalysisDashboard = () => {
  const { analysisData } = useAnalysis();
  if (!analysisData) {
    return <div>{"No hay resultados disponibles"}</div>;
  }

  const topIPs = Object.entries(analysisData.additional_data.ip_traffic)
    .sort((a, b) => b[1] - a[1]) // Ordenar por el valor de tráfico (el valor está en b[1])
    .slice(0, 5) // Tomar solo los 5 primeros
    .map(([ip, count]) => ({ ip, count }));

  

  const protocolData = Object.entries(analysisData.protocol_packets_result).map(([protocol, value]) => ({
    name: protocol,
    value: value
  }));

  const getTopPorts = (portsData, isOrigen = true) => {
    const ports = {}; // Usamos un objeto para acumular los puertos y el tráfico
  
    for (const [key, value] of Object.entries(portsData)) {
      // Según si es puerto de origen o destino, tomar el tráfico correspondiente
      const port = isOrigen ? value.puerto_origen : value.puerto_destino;
      const traffic = isOrigen ? value.suma_p_origen : value.suma_p_destino;
  
      // Si el puerto ya existe, acumulamos el tráfico, si no, lo iniciamos
      if (ports[port]) {
        ports[port] += traffic;
      } else {
        ports[port] = traffic;
      }
    }
  
    // Convertimos el objeto `ports` a un array y lo ordenamos por tráfico
    const sortedPorts = Object.entries(ports)
      .map(([port, traffic]) => ({ port, traffic })) // Convertimos el objeto a un array de objetos
      .sort((a, b) => b.traffic - a.traffic) // Ordenamos por tráfico
      .slice(0, 5); // Tomamos los 5 primeros
  
    return sortedPorts;
  };

  const topPortsOrigen = getTopPorts(analysisData.additional_data.port_traffic, true);
  const topPortsDestino = getTopPorts(analysisData.additional_data.port_traffic, false);


  const { active_connections } = analysisData.additional_data;
  const packetData = Object.keys(active_connections).map((key) => {
    const connection = active_connections[key];
    return {
      key: key,
      ipOrigen: connection.ip_origen,
      ipDestino: connection.ip_destino,
      puerto_origen: connection.puerto_origen,
      puerto_destino: connection.puerto_destino,
      protocolo: connection.protocolo,
      otros_protocolos: connection.otros_protocolos,
      numero_conexiones: connection.numero_conexiones,
    };
  });

  const ipOrigenFilters = [...new Set(packetData.map(item => item.ipOrigen))].map(ip => ({ text: ip, value: ip }));
  const ipDestinoFilters = [...new Set(packetData.map(item => item.ipDestino))].map(ip => ({ text: ip, value: ip }));
  const puerto_origenFilters = [...new Set(packetData.map(item => item.puerto_origen))].map(puerto_origen => ({ text: puerto_origen, value: puerto_origen }));
  const puerto_destinoFilters = [...new Set(packetData.map(item => item.puerto_destino))].map(puerto_destino => ({ text: puerto_destino, value: puerto_destino }));
  const protocoloFilters = [...new Set(packetData.map(item => item.protocolo))].map(protocolo => ({ text: protocolo, value: protocolo }));
  const otroprotocoloFilters = [...new Set(packetData.map(item => item.otros_protocolos))].map(otros_protocolos => ({ text: otros_protocolos, value: otros_protocolos }));

  const packetColumns = [
    { title: "IP Origen", dataIndex: "ipOrigen", key: "ipOrigen", filters: ipOrigenFilters, onFilter: (value, record) => record.ipOrigen && record.ipOrigen.includes(value), },
    { title: "IP Destino", dataIndex: "ipDestino", key: "ipDestino", filters: ipDestinoFilters, onFilter: (value, record) => record.ipDestino && record.ipDestino.includes(value),},
    { title: "Puerto Origen", dataIndex: "puerto_origen", key: "puerto_origen", filters: puerto_origenFilters, onFilter: (value, record) => record.puerto_origen && record.puerto_origen.includes(value),},
    { title: "Puerto Destino", dataIndex: "puerto_destino", key: "puerto_destino", filters: puerto_destinoFilters, onFilter: (value, record) => record.puerto_destino && record.puerto_destino.includes(value),},
    { title: "Protocolo", dataIndex: "protocolo", key: "protocolo", filters: protocoloFilters, onFilter: (value, record) => record.protocolo && record.protocolo.includes(value),},
    { title: "Otro Protocolo", dataIndex: "otros_protocolos", key: "otros_protocolos", filters: otroprotocoloFilters, onFilter: (value, record) => record.otros_protocolos && record.otros_protocolos.includes(value),},
    { title: "Número de Conexiones", dataIndex: "numero_conexiones", key: "numero_conexiones" },
  ];
  
  const { packet_sizes, network_errors } = analysisData.additional_data;
  const getTagColor = (type, value) => {
    switch (type) {
      case 'packet_size':
        if (value === 'small') return 'processing';
        if (value === 'medium') return 'warning';
        return 'error'; // Para "large"
      case 'retransmissions':
        return value > 0 ? 'warning' : 'default';
      case 'checksum_errors':
        return value > 0 ? 'default' : 'success';
      default:
        return 'default';
    }
  };

  const getReadableSize = (size) => {
    switch (size) {
      case 'small':
        return 'Paquetes Pequeños'; 
      case 'medium':
        return 'Paquetes Medianos';
      case 'large':
        return 'Paquetes Grandes';
      default:
        return size;
    }
  };
  
  const secure_protocols = analysisData.additional_data.secure_protocols || {};
  const insecure_protocols = analysisData.additional_data.insecure_protocols || {};

  const renderProtocolProgress = (protocols, isSecure) => {
    return Object.keys(protocols).map((protocol) => (
      <div key={protocol} style={{ margin: "0px", textAlign: "center" }}>
        <Progress
          type="circle"
          percent={100}
          status="active"
          strokeWidth={10}
          format={() => protocol} // Muestra el nombre del protocolo
          strokeColor={isSecure ? "#00A86B" : "red"} // Cambia el color del círculo según el protocolo
          strokeLinecap="round" // Hace que las líneas sean redondeadas, dando un efecto más suave
          style={{
            transform: "scale(0.5)", // Para hacer el círculo aún más pequeño si se desea
          }}
        />
      </div>
    ));
  };

  const getICMPColor = (icmpType) => {
    const positiveTypes = ["0"]; // Positivos
    const negativeTypes = ["3", "4", "5", "11", "12"]; // Negativos
    const informationTypes = ["14","9","10","8","13","14"]; // Informativos
    
    if (positiveTypes.includes(icmpType)) {
      return "green"; // Color verde para tipos positivos
    } else if (negativeTypes.includes(icmpType)) {
      return "red"; // Color rojo para tipos negativos
    } else if (informationTypes.includes(icmpType)){
      return "blue"; // Color azul para tipos informativos
    }
    return "gray"; // Color por defecto (si no está en la lista)
  };

  const anomalousTraffic = analysisData.additional_data.anomalous_traffic;
  const tcpStates = analysisData.additional_data.tcp_states;
  
  return (
    <div className="p-4">
      <Row gutter={[16, 16]}>
        {/* <Col xs={24} sm={12} md={12} lg={6} xl={6}>
          <Card title="Total de Paquetes" bordered={false}>
            <h2>{analysisData.total_packets_result}</h2>
          </Card>
        </Col> */}
        <Col xs={24} sm={24} md={24} lg={12} xl={12}>
          <Card title="Visión General de Tráfico" bordered={false}>
          <div>
              {packet_sizes && Object.keys(packet_sizes).map((size) => (
                <Tag color={getTagColor('packet_size', size)} key={size}>
                  {`${getReadableSize(size)}: ${packet_sizes[size]}`}
                </Tag>
              ))}
            </div>

            <div style={{ marginTop: '16px' }}>
              {network_errors && (
                <>
                  <Tag color={getTagColor('retransmissions', network_errors.retransmissions)}>
                    Retransmisiones: {network_errors.retransmissions}
                  </Tag>
                  <Tag color={getTagColor('checksum_errors', network_errors.checksum_errors)}>
                    Errores de Checksum: {network_errors.checksum_errors}
                  </Tag>
                </>
              )}
            </div>
            <Tabs defaultActiveKey="1" type="card" style={{ marginTop: '16px' }}>
              <TabPane tab="IP" key="1">
                <p>IPs con más tráfico</p>
                {topIPs && topIPs.length === 0 ? (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                ) : (
                  /* Gráfico de barras */
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={topIPs}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="ip" />
                      <YAxis />
                      <Tooltip/>
                      <Bar dataKey="count">
                        {topIPs.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                  )}
              
                
              </TabPane>

              <TabPane tab="Puertos" key="2">
              <p>Puertos con más tráfico</p>

              {/* Gráfico de Puertos Origen */}
              <h3>Puertos Origen</h3>
              {topPortsOrigen && topPortsOrigen.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={topPortsOrigen}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="port" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="traffic">
                      {topPortsOrigen.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}

              {/* Gráfico de Puertos Destino */}
              <h3>Puertos Destino</h3>
              {topPortsDestino && topPortsDestino.length === 0 ? (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={topPortsDestino}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="port" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="traffic">
                      {topPortsDestino.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
              </TabPane>


              <TabPane tab="Protocolos de Seguridad" key="3">
                <Row gutter={[16, 16]}>
                  <Col span={12}>
                    <h3>Protocolos Seguros</h3>
                    {secure_protocols && Object.keys(secure_protocols).length === 0 ? (
                      <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    ) : (
                      <div style={{ display: "flex", flexWrap: "wrap" }}>
                        {renderProtocolProgress(secure_protocols, true)}
                      </div>
                    )}
                  </Col>
                  <Col span={12}>
                    <h3>Protocolos Inseguros</h3>
                    {insecure_protocols && Object.keys(insecure_protocols).length === 0 ? (
                      <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    ) : (
                      <div style={{ display: "flex", flexWrap: "wrap" }}>
                        {renderProtocolProgress(insecure_protocols, false)}
                      </div>
                    )}
                  </Col>
                </Row>
              </TabPane>

              
              <TabPane tab="ICMP" key="4">
                <Row gutter={[16, 16]}>
                  <Col span={24}>
                    <h3>Tipos de ICMP</h3>
                    <List
                      dataSource={Object.entries(analysisData.additional_data.icmp_types)} // Convierte el objeto a un array de [clave, valor]
                      renderItem={([key, value]) => (
                        <List.Item>
                          <List.Item.Meta
                            title={value.name} // Muestra el tipo de ICMP
                            description={`Veces: ${value.count}`}  // Muestra el contador del tipo ICMP
                          />
                          {/* Aquí asignas un color dependiendo del tipo de ICMP */}
                          <Tag color={getICMPColor(key)}>Código ICMP {key}</Tag>
                        </List.Item>
                      )}
                    />
                  </Col>
                </Row>
              </TabPane>

              <TabPane tab="Dominios Extraídos" key="5">
                <Row gutter={[16, 16]}>
                  <Col span={24}>
                    <h3>IPs & URLs Extraídas</h3>
                    <List
                      dataSource={analysisData.extracted_urls} // Asumiendo que extracted_urls es un array de URLs
                      renderItem={(url, index) => (
                        <List.Item>
                          <List.Item.Meta
                            avatar={<img src="https://img.icons8.com/ios/50/000000/domain.png" alt="url-icon" />} // Icono para las URLs
                            title={<a href={url} target="_blank" rel="noopener noreferrer">{url}</a>} // Enlace clickeable
                            description={`Dominio número ${index + 1}`} // Descripción opcional
                          />
                          {/* Aquí puedes añadir un tag o alguna otra decoración */}
                          <Tag color="purple" size="large" style={{ fontSize: '18px', padding: '5px 8px' }}>URL</Tag>
                        </List.Item>
                      )}
                    />
                  </Col>
                </Row>
              </TabPane>


            </Tabs>
          </Card>
        </Col>

        <Col xs={24} sm={24} md={24} lg={12} xl={12}>
          <Card title="Protocolos de la Última Capa">
              <ResponsiveContainer width="100%" height={300}> {/* 🔹 Cambio: Ajuste dinámico */}
                <PieChart>
                  <Pie data={protocolData} dataKey="value" outerRadius={80}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
          </Card>
          <Card title="Valoración usando la API de VirusTotal" className="mt-4">
            {analysisData.result_virus_total && analysisData.result_virus_total.error ? (
              <div style={{ padding: "20px", textAlign: "center" }}>
                <p style={{ fontSize: "16px", color: "red" }}>
                  Error: {analysisData.result_virus_total.error}
                </p>
                <p style={{ fontSize: "14px", color: "#888" }}>
                  No se pudo obtener los resultados de VirusTotal. Por favor, inténtalo más tarde.
                </p>
              </div>
            ) : Object.keys(analysisData.result_virus_total).length > 0 ? (
              <Collapse>
                {Object.entries(analysisData.result_virus_total).map(([key, value], index) => (
                  <Collapse.Panel header={key} key={index}>
                    <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: "14px" }}>
                      {typeof value === "object" ? JSON.stringify(value, null, 2) : value}
                    </pre>
                  </Collapse.Panel>
                ))}
              </Collapse>
            ) : (
              <div style={{ padding: "20px", textAlign: "center" }}>
                <p style={{ fontSize: "16px", color: "#888" }}>
                  No se encontraron resultados relacionados con la API de VirusTotal.
                </p>
                <p style={{ fontSize: "14px", color: "#666" }}>
                  Esto puede incluir direcciones IP, URLs, análisis de malware, etc.
                </p>
              </div>
            )}
          </Card>
        </Col>
      </Row>
      
      <Row>
        <Col xs={24} sm={24} md={24} lg={24} xl={24}>
          <Card title={`Lista de Paquetes Capturados: ${analysisData.total_packets_result}  /  Tiempo de Captura: ${analysisData.duration_packet}.`} className="mt-4">
            <Table columns={packetColumns} dataSource={packetData} pagination={{ pageSize: 20 }} scroll={{ x: "max-content" }} /> {/* 🔹 Cambio: scroll en tablas */}
        </Card>
        </Col>
      </Row>
      
      <Card title="Detección de Anomalías" className="mt-4">
        {/* Mostramos los alertas de tráfico anómalo */}
        {anomalousTraffic && Object.keys(anomalousTraffic).length > 0 ? (
          Object.keys(anomalousTraffic).map((key, index) => (
            <Alert
              key={index}
              message={<span style={{ fontSize: "10px" }}>{key}</span>}  // Aquí mostramos la clave, como "Ataque DDoS al puerto 52805"
              description={anomalousTraffic[key].mensaje}  // Mostramos el mensaje dentro de la clave
              type="warning"
              showIcon
              style={{ fontSize: "11px", padding: "5px", marginBottom: "10px" }}
            />
          ))
        ) : (
          <Alert
            message={<span style={{ fontSize: "10px" }}>No hay resultados disponibles</span>}
            description="No se ha detectado ningún tráfico inusual o anómalo en la red."
            type="info"
            showIcon
            style={{ fontSize: "12px", padding: "10px", marginBottom: "10px" }} 
          />
        )}

        {/* Mostramos los estados TCP */}
        {tcpStates && Object.keys(tcpStates).length > 0 ? (
        Object.keys(tcpStates).map((state, index) => (
            <Alert
              key={index}
              message={<span style={{ fontSize: "10px" }}>{state}</span>}  // Aquí mostramos el estado TCP, como "SYN Flood"
              description={tcpStates[state].mensaje}  // Mostramos el mensaje de cada estado
              type="warning"
              showIcon
              style={{ fontSize: "11px", padding: "5px", marginBottom: "10px" }}
            />
          ))
        ) : (
          <Alert
            message={<span style={{ fontSize: "10px" }}>No hay resultados disponibles</span>}
            description="No se ha detectado ningún estado TCP anómalo en la red."
            type="info"
            showIcon
            style={{ fontSize: "12px", padding: "10px", marginBottom: "10px" }} 
          />
        )}
      </Card>
    </div>
  );
};

export default AnalysisDashboard;