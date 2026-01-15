package main

import "sync"

type VMPool struct {
    size int
    jobs chan string
    wg   sync.WaitGroup
}

func NewVMPool(size int) *VMPool {
    if size < 1 {
        size = 1
    }
    return &VMPool{
        size: size,
        jobs: make(chan string, size*4),
    }
}

func (p *VMPool) Start(worker func(string)) {
    for i := 0; i < p.size; i++ {
        p.wg.Add(1)
        go func() {
            defer p.wg.Done()
            for path := range p.jobs {
                worker(path)
            }
        }()
    }
}

func (p *VMPool) Submit(path string) bool {
    select {
    case p.jobs <- path:
        return true
    default:
        return false
    }
}
