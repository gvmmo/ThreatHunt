import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Input,
  Select,
  VStack,
  Heading,
  Text,
  useToast,
  Checkbox,
  CheckboxGroup,
  Stack,
  Divider,
  Card,
  CardBody,
} from '@chakra-ui/react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

function NewScan() {
  const [tools, setTools] = useState({ passive: [], active: [] });
  const [selectedTools, setSelectedTools] = useState([]);
  const [scanType, setScanType] = useState('passive');
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('domain');
  const [activeTargets, setActiveTargets] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const toast = useToast();
  const navigate = useNavigate();

  // Fetch available tools on component mount
  useEffect(() => {
    const fetchTools = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/tools`);
        setTools(response.data);
      } catch (error) {
        toast({
          title: 'Error fetching tools',
          description: error.message,
          status: 'error',
          duration: 5000,
        });
      }
    };
    fetchTools();
  }, []);

  // Update selected tools when scan type changes
  useEffect(() => {
    setSelectedTools(tools[scanType] || []);
  }, [scanType, tools]);

  const handleScanTypeChange = (e) => {
    const newScanType = e.target.value;
    setScanType(newScanType);
    setSelectedTools(tools[newScanType] || []);
  };

  const handleToolToggle = (tool) => {
    setSelectedTools(prev => 
      prev.includes(tool)
        ? prev.filter(t => t !== tool)
        : [...prev, tool]
    );
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan/start`, {
        target,
        target_type: targetType,
        scan_type: scanType,
        tools: selectedTools,
        active_targets: activeTargets,
        user_id: 'user123', // Replace with actual user ID from auth
      });

      toast({
        title: 'Scan started',
        description: 'Your scan has been queued successfully',
        status: 'success',
        duration: 5000,
      });

      // Navigate to scan details page
      navigate(`/scan/${response.data.scan_id}`);
    } catch (error) {
      toast({
        title: 'Error starting scan',
        description: error.message,
        status: 'error',
        duration: 5000,
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Box>
      <Heading mb={6}>New Scan</Heading>
      <form onSubmit={handleSubmit}>
        <VStack spacing={6} align="stretch">
          <Card>
            <CardBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>Target</FormLabel>
                  <Input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Enter domain or IP address"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Target Type</FormLabel>
                  <Select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                  </Select>
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>Scan Type</FormLabel>
                  <Select
                    value={scanType}
                    onChange={handleScanTypeChange}
                  >
                    <option value="passive">Passive</option>
                    <option value="active">Active</option>
                  </Select>
                </FormControl>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={4}>
                <Heading size="md">Available Tools</Heading>
                <Text>Select tools to use for this scan:</Text>
                <CheckboxGroup>
                  <Stack spacing={2}>
                    {tools[scanType]?.map((tool) => (
                      <Checkbox
                        key={tool}
                        isChecked={selectedTools.includes(tool)}
                        onChange={() => handleToolToggle(tool)}
                      >
                        {tool}
                      </Checkbox>
                    ))}
                  </Stack>
                </CheckboxGroup>
              </VStack>
            </CardBody>
          </Card>

          {scanType === 'active' && (
            <Card>
              <CardBody>
                <VStack spacing={4}>
                  <Heading size="md">Active Scan Targets</Heading>
                  <Text>
                    Enter additional targets for active scanning (one per line):
                  </Text>
                  <Input
                    as="textarea"
                    value={activeTargets.join('\n')}
                    onChange={(e) => setActiveTargets(e.target.value.split('\n'))}
                    placeholder="Enter targets..."
                    rows={4}
                  />
                </VStack>
              </CardBody>
            </Card>
          )}

          <Button
            type="submit"
            colorScheme="blue"
            size="lg"
            isLoading={isLoading}
            loadingText="Starting scan..."
          >
            Start Scan
          </Button>
        </VStack>
      </form>
    </Box>
  );
}

export default NewScan; 