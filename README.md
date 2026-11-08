**Network Intrusion Detection Using Graphs in C++ :**

**Project Description**:

A C++-based Network Intrusion Detection System that uses graph data structures and algorithms to analyze network connections, identify potentially suspicious computers using a threshold-based approach, and generate risk reports and network statistics.

**Abstract**:

This project demonstrates the application of graph data structures in basic network security analysis. Computers are represented as vertices, and connections between computers are represented as edges. The system uses an adjacency list to store network connections and applies BFS and DFS algorithms to explore network connectivity. It analyzes the number of connections associated with each computer and flags computers that exceed a predefined threshold. It also provides network management, risk reports, and network statistics through a menu-driven interface.

**Features**:
- Graph representation using an adjacency list.
- Add and remove network connections.
- Display the network structure.
- Threshold-based suspicious connection detection.
- Risk score and risk level generation.
- BFS and DFS graph traversal.
- Network statistics.
- Customizable detection threshold.
- Input validation.

**Technologies Used**:
- Programming Language: C++
- Data Structure: Graph (Adjacency List)
- Algorithms: BFS and DFS
- Libraries: STL (Vector, Queue, Algorithm)

**Requirements**:

**Hardware Requirements:**
- Computer or laptop
- Minimum 4 GB RAM
- Intel Core i3 or equivalent processor
  
**Software Requirements**:
- Windows, Linux, or macOS
- C++ compiler (GCC/G++ or MinGW)
- Visual Studio Code, Code::Blocks, or Dev-C++

**Methodology**:
1. Accept the number of computers and their network connections.
2. Represent the network as an undirected graph using an adjacency list.
3. Validate and manage network connections.
4. Calculate the degree of each computer.
5. Compare the connection count with the configured threshold.
6. Flag computers whose connection count exceeds the threshold.
7. Apply BFS and DFS to explore network connectivity.
8. Generate risk reports and network statistics.

**Future Enhancements**:

1.**Real-Time Network Monitoring**: Integrate live network traffic monitoring to analyze actual network activities.

2.**Advanced Detection Techniques**: Implement multiple detection rules to identify different suspicious connection patterns.

3.**Machine Learning Integration**: Use machine learning techniques to improve the identification of unusual network behavior.

4.**Graphical User Interface**: Develop a user-friendly dashboard to visualize network connections and risk reports.

5.**Alert System**: Generate alerts whenever potentially suspicious network activity is detected.

6.**Detailed Traffic Analysis**: Analyze connection frequency, timestamps, and traffic patterns for better detection.

**How to Run**:

Compile the program:

g++ -std=c++11 main.cpp -o network_ids

Run the program:

./network_ids

On Windows, run:

network_ids.exe

**conclusion**:

This project demonstrates how graph data structures and algorithms can be used for basic network security analysis. It helps understand network connectivity, threshold-based detection, and graph traversal using C++.

**Note**:

This is an educational, rule-based implementation. A high connection count does not necessarily indicate an actual intrusion. The system does not monitor live network traffic or confirm real cyberattacks.
