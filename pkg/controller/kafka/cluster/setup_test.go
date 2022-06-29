package cluster

import (
	"testing"
)

func Test_zooKeeperToClusterEndpoint(t *testing.T) {
	type args struct {
		connString string
		srcPort    string
		dstPort    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "OK",
			args: args{
				connString: "z-1.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9092,z-2.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9092,z-3.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9092",
				srcPort:    "9092",
				dstPort:    "9094",
			},
			want: "b-1.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9094,b-2.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9094,b-3.kafkacluster.xxxxxx.c4.kafka.eu-north-1.amazonaws.com:9094",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := zooKeeperToClusterEndpoint(tt.args.connString, tt.args.srcPort, tt.args.dstPort); got != tt.want {
				t.Errorf("zooKeeperToClusterEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
