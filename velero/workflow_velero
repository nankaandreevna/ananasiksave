# note-commands

# Process of creating backup (look at folder from-start)
  * 1 Create a Docker Image and specify provider (in this case gcp)
  * 2 Create a script to install velero on your cluster
  * 3 Creating Backup location
  * 4 Schedule Backup

# Create a backup 
velero backup create test-exlude-1 --include-namespaces vault --storage-location=carbon-app-cluster-backup --ttl=72h

# Details of created backup. 
velero backup describe test 
velero backup logs test 

# Restore back up  
velero restore create --from-backup backup-1 --include-namespaces vault

# Exclude from back up, need to add a label, if true=it will be exluded.
velero.io/exclude-from-backup: "true"

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  annotations:
    pv.kubernetes.io/bind-completed: "yes"
    pv.kubernetes.io/bound-by-controller: "yes"
    volume.beta.kubernetes.io/storage-provisioner: kubernetes.io/gce-pd
    volume.kubernetes.io/selected-node: gke-carbon-us-central1-s-kite-1-green-31572d70-29rm
  labels:
    app: mysql-operator
    release: mysql-operator
    velero.io/exclude-from-backup: "true"
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
  volumeMode: Filesystem
  volumeName: pvc-test
status:
  accessModes:
  - ReadWriteOnce
  capacity:
    storage: 10Gi
  phase: Bound    
```

# Freeze before backup made, unfreeze after it made. Should be added to annotations
```
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: {{ template "mysql-operator.fullname" . }}
  labels:
    app: {{ template "mysql-operator.name" . }}
    chart: {{ template "mysql-operator.chart" . }}
    release: {{ .Release.Name }}
    heritage: {{ .Release.Service }}
spec:
  replicas: {{ .Values.replicas }}
  serviceName: {{ template "mysql-operator.orc-service-name" . }}
  podManagementPolicy: Parallel
  selector:
    matchLabels:
      app: {{ template "mysql-operator.name" . }}
      release: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app: {{ template "mysql-operator.name" . }}
        release: {{ .Release.Name }}
      annotations:
        checksum/config: {{ include (print $.Template.BasePath "/orc-config.yaml") . | sha256sum }}
        checksum/secret: {{ include (print $.Template.BasePath "/orc-secret.yaml") . | sha256sum }}
        backup.velero.io/backup-volumes: data
        pre.hook.backup.velero.io/command: '["/sbin/fsfreeze", "--freeze", "/var/lib/mysql"]'
        pre.hook.backup.velero.io/container: fsfreeze
        post.hook.backup.velero.io/command: '["/sbin/fsfreeze", "--unfreeze", "/var/lib/mysql"]'
        post.hook.backup.velero.io/container: fsfreeze
    spec:
      serviceAccountName: {{ template "mysql-operator.serviceAccountName" . }}
      {{- if .Values.imagePullSecrets }}
      imagePullSecrets:                                                       
```