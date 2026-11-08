#include <iostream>
#include <vector>
#include <queue>
#include <algorithm>
#include <limits>
#include <string>
using namespace std;

class NetworkIDS {
private:
    int n;
    vector<vector<int>> graph;

public:
    NetworkIDS(int computers) {
        n = computers;
        graph.resize(n);
    }

    bool validID(int u) {
        return u >= 0 && u < n;
    }

    bool addConnection(int u, int v) {
        if (!validID(u) || !validID(v) || u == v)
            return false;

        if (find(graph[u].begin(), graph[u].end(), v)
            != graph[u].end())
            return false;

        graph[u].push_back(v);
        graph[v].push_back(u);
        return true;
    }

    bool removeConnection(int u, int v) {
        if (!validID(u) || !validID(v))
            return false;

        auto it1 = find(graph[u].begin(), graph[u].end(), v);
        auto it2 = find(graph[v].begin(), graph[v].end(), u);

        // Check both connections before removing either one
        if (it1 == graph[u].end() ||
            it2 == graph[v].end())
            return false;

        graph[u].erase(it1);
        graph[v].erase(it2);
        return true;
    }

    void displayNetwork() {
        cout << "\n========== NETWORK GRAPH ==========\n";

        for (int i = 0; i < n; i++) {
            cout << "Computer " << i << " -> ";

            if (graph[i].empty()) {
                cout << "No connections";
            } else {
                for (int v : graph[i])
                    cout << v << " ";
            }

            cout << "\n";
        }
    }

    void analyzeNetwork(int threshold) {
        int totalEdges = 0;
        int suspicious = 0;
        int lowRisk = 0;

        cout << "\n========== NETWORK INTRUSION DETECTION SYSTEM ==========\n";

        for (int i = 0; i < n; i++) {
            totalEdges += graph[i].size();
        }

        totalEdges /= 2;

        cout << "Total Computers   : " << n << "\n";
        cout << "Total Connections : " << totalEdges << "\n";
        cout << "Detection Rule    : Flag if connections > "
             << threshold << "\n";

        cout << "\n========== COMPUTER RISK REPORT ==========\n";

        for (int i = 0; i < n; i++) {
            int degree = graph[i].size();
            int riskScore = 0;
            string riskLevel;
            string reason = "No suspicious activity detected by this rule";

            // Rule 1: High number of connections
            if (degree > threshold) {
                riskScore += 70;
                reason = "Connection count exceeds threshold";
            }

            // Rule 2: Isolated computer
            if (degree == 0) {
                reason = "No network connections";
            }

            // Demonstration score, not a probability
            if (riskScore >= 70) {
                riskLevel = "HIGH";
                suspicious++;
            } else {
                riskLevel = "LOW";
                lowRisk++;
            }

            cout << "\nComputer " << i << "\n";
            cout << "Connections : " << degree << "\n";
            cout << "Risk Score  : " << riskScore << "/100\n";
            cout << "Risk Level  : " << riskLevel << "\n";
            cout << "Reason      : " << reason << "\n";
        }

        cout << "\n========== FINAL SUMMARY ==========\n";
        cout << "Computers Analyzed     : " << n << "\n";
        cout << "Potentially Suspicious : " << suspicious << "\n";
        cout << "Low-Risk by This Rule  : " << lowRisk << "\n";

        cout << "\nRecommendation:\n";

        if (suspicious > 0) {
            cout << "Investigate flagged computers' connection activity.\n";
        } else {
            cout << "No computers exceeded the configured threshold.\n";
        }

        cout << "Note: These rules do not prove an actual attack.\n";
    }

    void BFS(int start) {
        if (!validID(start)) {
            cout << "Invalid computer ID.\n";
            return;
        }

        vector<bool> visited(n, false);
        queue<int> q;

        visited[start] = true;
        q.push(start);

        cout << "BFS traversal: ";

        while (!q.empty()) {
            int u = q.front();
            q.pop();

            cout << u << " ";

            for (int v : graph[u]) {
                if (!visited[v]) {
                    visited[v] = true;
                    q.push(v);
                }
            }
        }

        cout << "\n";
    }

    void DFS(int start) {
        if (!validID(start)) {
            cout << "Invalid computer ID.\n";
            return;
        }

        vector<bool> visited(n, false);
        vector<int> st;
        st.push_back(start);

        cout << "DFS traversal: ";

        while (!st.empty()) {
            int u = st.back();
            st.pop_back();

            if (visited[u])
                continue;

            visited[u] = true;
            cout << u << " ";

            for (auto it = graph[u].rbegin();
                 it != graph[u].rend(); ++it) {
                if (!visited[*it])
                    st.push_back(*it);
            }
        }

        cout << "\n";
    }

    void statistics(int threshold) {
        int edges = 0;
        int isolated = 0;
        int flagged = 0;

        for (int i = 0; i < n; i++) {
            edges += graph[i].size();

            if (graph[i].empty())
                isolated++;

            if ((int)graph[i].size() > threshold)
                flagged++;
        }

        cout << "\n========== NETWORK STATISTICS ==========\n";
        cout << "Computers       : " << n << "\n";
        cout << "Connections     : " << edges / 2 << "\n";
        cout << "Isolated Nodes  : " << isolated << "\n";
        cout << "Flagged Nodes   : " << flagged << "\n";
    }
};

int readInt(const string& prompt) {
    int value;

    while (true) {
        cout << prompt;

        if (cin >> value)
            return value;

        cout << "Invalid input. Enter an integer.\n";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
}

int main() {
    int n;

    do {
        n = readInt("Enter number of computers: ");

        if (n <= 0)
            cout << "Enter at least one computer.\n";

    } while (n <= 0);

    NetworkIDS network(n);

    int m;

    do {
        m = readInt("Enter number of connections: ");

        if (m < 0)
            cout << "Connections cannot be negative.\n";

    } while (m < 0);

    cout << "Enter each connection as two computer IDs.\n";

    for (int i = 0; i < m; i++) {
        int u = readInt("First computer: ");
        int v = readInt("Second computer: ");

        if (!network.addConnection(u, v)) {
            cout << "Invalid or duplicate connection. Try again.\n";
            i--;
        }
    }

    int threshold = 3;
    int choice;

    do {
        cout << "\n===== MAIN MENU =====\n";
        cout << "1. Display Network\n";
        cout << "2. Run Intrusion Analysis\n";
        cout << "3. Add Connection\n";
        cout << "4. Remove Connection\n";
        cout << "5. BFS Traversal\n";
        cout << "6. DFS Traversal\n";
        cout << "7. Network Statistics\n";
        cout << "8. Change Threshold\n";
        cout << "0. Exit\n";

        choice = readInt("Enter choice: ");

        switch (choice) {
            case 1:
                network.displayNetwork();
                break;

            case 2:
                network.analyzeNetwork(threshold);
                break;

            case 3: {
                int u = readInt("First computer: ");
                int v = readInt("Second computer: ");

                if (network.addConnection(u, v))
                    cout << "Connection added.\n";
                else
                    cout << "Cannot add connection.\n";

                break;
            }

            case 4: {
                int u = readInt("First computer: ");
                int v = readInt("Second computer: ");

                if (network.removeConnection(u, v))
                    cout << "Connection removed.\n";
                else
                    cout << "Connection not found or invalid IDs.\n";

                break;
            }

            case 5: {
                int start = readInt("Starting computer: ");
                network.BFS(start);
                break;
            }

            case 6: {
                int start = readInt("Starting computer: ");
                network.DFS(start);
                break;
            }

            case 7:
                network.statistics(threshold);
                break;

            case 8: {
                int newThreshold;

                do {
                    newThreshold = readInt("Enter new threshold: ");

                    if (newThreshold < 0)
                        cout << "Threshold cannot be negative.\n";

                } while (newThreshold < 0);

                threshold = newThreshold;
                cout << "Threshold updated.\n";
                break;
            }

            case 0:
                cout << "Thank you for using Network IDS!\n";
                break;

            default:
                cout << "Invalid choice. Try again.\n";
        }

    } while (choice != 0);

    return 0;
}
