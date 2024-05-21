package plugin

import (
	"fmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"k8s.io/client-go/kubernetes"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/rest"
)

type PodServiceInfo struct {
	Type           string
	PodName        string
	DeploymentName string
	ServiceName    string
}

type ClusterCache struct {
	mu         *sync.RWMutex
	ipPodCache map[string]PodServiceInfo
}

func (cc *ClusterCache) Get(IP string) (PodServiceInfo, bool) {
	cc.mu.RLock()
	defer cc.mu.Unlock()
	value, ok := cc.ipPodCache[IP]
	return value, ok

}
func (cc *ClusterCache) Set(IP string, pi PodServiceInfo) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.ipPodCache[IP] = pi

}
func (cc *ClusterCache) Delete(IP string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	delete(cc.ipPodCache, IP)

}
func convertToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		// Handle conversion error gracefully, e.g., log error and return default value
		fmt.Printf("Error converting %s to int: %v\n", s, err)
		return 0 // Default value (or handle as appropriate)
	}
	return i
}

func random(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func extractdata(body string) map[string]string {

	pairs := strings.Split(body, " ")

	// Initialize a map to store extracted values
	dataMap := make(map[string]string)

	// Loop through each key-value pair
	for _, pair := range pairs {
		// Split each pair by '=' to separate key and value
		parts := strings.Split(pair, "=")
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			dataMap[key] = value
		}
	}
	return dataMap
}

func ResolveIp(remoteIP string) string {
	return ""
}

func getK8sClient(ctxlogger log.Logger) *kubernetes.Clientset {
	config, err := rest.InClusterConfig()

	if err != nil {
		ctxlogger.Error("Error creating Kubernetes config: %v\n", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		ctxlogger.Error("Error creating Kubernetes ClientSet: %v\n", err)
	}
	return clientset
}
