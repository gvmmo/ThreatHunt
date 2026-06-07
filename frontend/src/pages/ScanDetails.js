import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
  Box,
  Heading,
  Text,
  VStack,
  HStack,
  Badge,
  Progress,
  Card,
  CardBody,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
} from '@chakra-ui/react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

function ScanDetails() {
  const { scanId } = useParams();
  const [scanData, setScanData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchScanData = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/scan/${scanId}`);
        setScanData(response.data);
      } catch (error) {
        console.error('Error fetching scan data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    // Initial fetch
    fetchScanData();

    // Set up polling for active scans
    const pollInterval = setInterval(() => {
      if (scanData?.status === 'running' || scanData?.status === 'queued') {
        fetchScanData();
      }
    }, 5000);

    return () => clearInterval(pollInterval);
  }, [scanId]);

  if (isLoading) {
    return <Text>Loading scan details...</Text>;
  }

  if (!scanData) {
    return <Text>Scan not found</Text>;
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return 'green';
      case 'running':
        return 'blue';
      case 'failed':
        return 'red';
      default:
        return 'gray';
    }
  };

  return (
    <Box>
      <VStack spacing={6} align="stretch">
        <Card>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <HStack justify="space-between">
                <Heading size="md">Scan Details</Heading>
                <Badge colorScheme={getStatusColor(scanData.status)}>
                  {scanData.status.toUpperCase()}
                </Badge>
              </HStack>

              <Box>
                <Text fontWeight="bold">Target:</Text>
                <Text>{scanData.results?.scan_info?.target}</Text>
              </Box>

              <Box>
                <Text fontWeight="bold">Scan Type:</Text>
                <Text>{scanData.results?.scan_info?.scan_type}</Text>
              </Box>

              {scanData.status === 'running' && scanData.progress && (
                <Box>
                  <Text fontWeight="bold">Progress:</Text>
                  <Progress
                    value={scanData.progress.percentage}
                    size="sm"
                    colorScheme="blue"
                    mb={2}
                  />
                  <Text fontSize="sm">
                    Current tool: {scanData.progress.current_tool}
                  </Text>
                </Box>
              )}

              {scanData.error && (
                <Box bg="red.50" p={4} borderRadius="md">
                  <Text color="red.500">Error: {scanData.error}</Text>
                </Box>
              )}
            </VStack>
          </CardBody>
        </Card>

        {scanData.results && (
          <Card>
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Heading size="md">Discovered Assets</Heading>
                <Accordion allowMultiple>
                  {Object.entries(scanData.results.assets || {}).map(([id, asset]) => (
                    <AccordionItem key={id}>
                      <h2>
                        <AccordionButton>
                          <Box flex="1" textAlign="left">
                            <Text fontWeight="bold">{asset.identifier}</Text>
                            <Text fontSize="sm" color="gray.500">
                              Type: {asset.type}
                            </Text>
                          </Box>
                          <AccordionIcon />
                        </AccordionButton>
                      </h2>
                      <AccordionPanel pb={4}>
                        <VStack align="stretch" spacing={4}>
                          {asset.osint_data && (
                            <>
                              {asset.osint_data.dns && (
                                <Box>
                                  <Text fontWeight="bold">DNS Records:</Text>
                                  <Table size="sm">
                                    <Thead>
                                      <Tr>
                                        <Th>Type</Th>
                                        <Th>Value</Th>
                                      </Tr>
                                    </Thead>
                                    <Tbody>
                                      {Object.entries(asset.osint_data.dns).map(([type, value]) => (
                                        <Tr key={type}>
                                          <Td>{type}</Td>
                                          <Td>{value}</Td>
                                        </Tr>
                                      ))}
                                    </Tbody>
                                  </Table>
                                </Box>
                              )}

                              {asset.osint_data.web_technologies && (
                                <Box>
                                  <Text fontWeight="bold">Web Technologies:</Text>
                                  <Table size="sm">
                                    <Thead>
                                      <Tr>
                                        <Th>Technology</Th>
                                        <Th>Version</Th>
                                      </Tr>
                                    </Thead>
                                    <Tbody>
                                      {Object.entries(asset.osint_data.web_technologies).map(([tech, version]) => (
                                        <Tr key={tech}>
                                          <Td>{tech}</Td>
                                          <Td>{version}</Td>
                                        </Tr>
                                      ))}
                                    </Tbody>
                                  </Table>
                                </Box>
                              )}

                              {asset.osint_data.shodan && (
                                <Box>
                                  <Text fontWeight="bold">Shodan Data:</Text>
                                  <Text fontSize="sm" whiteSpace="pre-wrap">
                                    {JSON.stringify(asset.osint_data.shodan, null, 2)}
                                  </Text>
                                </Box>
                              )}
                            </>
                          )}
                        </VStack>
                      </AccordionPanel>
                    </AccordionItem>
                  ))}
                </Accordion>
              </VStack>
            </CardBody>
          </Card>
        )}
      </VStack>
    </Box>
  );
}

export default ScanDetails; 