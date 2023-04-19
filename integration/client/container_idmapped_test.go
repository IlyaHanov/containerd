//go:build linux
// +build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package client

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/snapshots/overlay/overlayutils"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestIDMappedOverlay(t *testing.T) {
	var (
		upperPath   string
		snapshotter = "overlayfs"
		ctx, cancel = testContext(t)
		id          = t.Name()
	)
	defer cancel()

	if ok, err := overlayutils.SupportsIDMappedMounts(); err != nil || !ok {
		t.Skip("overlayfs doesn't support idmapped mounts")
	}

	client, err := newClient(t, address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	image, err := client.GetImage(ctx, testImage)
	if err != nil {
		t.Fatal(err)
	}

	hostID := uint32(33)
	contID := uint32(0)
	length := uint32(65536)

	uidMap := specs.LinuxIDMapping{
		ContainerID: contID,
		HostID:      hostID,
		Size:        length,
	}
	gidMap := specs.LinuxIDMapping{
		ContainerID: contID,
		HostID:      hostID,
		Size:        length,
	}

	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(image),
		containerd.WithImageConfigLabels(image),
		containerd.WithSnapshotter(snapshotter),
		containerd.WithNewSnapshot(id, image, containerd.WithRemapperLabels(uidMap.ContainerID, uidMap.HostID, gidMap.ContainerID, gidMap.HostID, length)),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithUserNamespace([]specs.LinuxIDMapping{uidMap}, []specs.LinuxIDMapping{gidMap}),
			longCommand))
	if err != nil {
		t.Fatal(err)
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	task, err := container.NewTask(ctx, empty())
	if err != nil {
		t.Fatal(err)
	}
	defer task.Delete(ctx)

	finishedC, err := task.Wait(ctx)
	if err != nil {
		t.Error(err)
	}

	if err := task.Start(ctx); err != nil {
		t.Fatal(err)
	}

	o := client.SnapshotService(snapshotter)
	mounts, err := o.Mounts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	for _, o := range mounts[0].Options {
		if strings.HasPrefix(o, "upperdir=") {
			upperPath = strings.TrimPrefix(o, "upperdir=")
		}
	}

	st, err := os.Stat(upperPath)
	if err != nil {
		t.Errorf("failed to stat %s", upperPath)
	}
	stat := st.Sys().(*syscall.Stat_t)
	if stat.Uid != uidMap.HostID || stat.Gid != gidMap.HostID {
		t.Errorf("bad mapping: expected {uid: %d, gid: %d}; real {uid: %d, gid: %d}", uidMap.HostID, gidMap.HostID, int(stat.Uid), int(stat.Gid))
	}

	if err := task.Kill(ctx, syscall.SIGKILL); err != nil {
		t.Error(err)
	}

	status := <-finishedC
	_, _, err = status.Result()
	if err != nil {
		t.Fatal(err)
	}
}
