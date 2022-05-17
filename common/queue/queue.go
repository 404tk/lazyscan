package queue

import (
	"container/list"
	"sync"
)

type Queue struct {
	data *list.List
	lock *sync.Mutex
}

func NewQueue() *Queue {
	q := new(Queue)
	q.data = list.New()
	q.lock = new(sync.Mutex)
	return q
}

func (q *Queue) Clear() {
	defer q.lock.Unlock()
	q.lock.Lock()
	q.data.Init()
}

func (q *Queue) Push(v interface{}) {
	defer q.lock.Unlock()
	q.lock.Lock()
	q.data.PushFront(v)
}

func (q *Queue) Pop() interface{} {
	defer q.lock.Unlock()
	q.lock.Lock()
	iter := q.data.Back()
	v := iter.Value
	q.data.Remove(iter)
	return v
}

func (q *Queue) Length() int {
	defer q.lock.Unlock()
	q.lock.Lock()
	length := q.data.Len()
	return length
}

func (q *Queue) Dump() (v []interface{}) {
	for iter := q.data.Back(); iter != nil; iter = iter.Prev() {
		v = append(v, iter.Value)
	}
	return
}
