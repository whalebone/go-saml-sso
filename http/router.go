package http

import (
	"log"
	"net/http"
	"sync"
	"time"
)

type RouterSwapper interface {
	Swap(newRouter *http.ServeMux)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	PeriodicRefresh(interval time.Duration, quit <-chan struct{}, newRouterGeneratorFc RouterGeneratorFc)
}

type routerSwapper struct {
	mu     sync.RWMutex
	router *http.ServeMux
}

func NewRouterSwapper(router *http.ServeMux) RouterSwapper {
	return &routerSwapper{
		router: router,
	}
}

func (rs *routerSwapper) Swap(newRouter *http.ServeMux) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.router = newRouter
}

func (rs *routerSwapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	rs.router.ServeHTTP(w, r)
}

type RouterGeneratorFc func() (*http.ServeMux, error)

func (rs *routerSwapper) PeriodicRefresh(interval time.Duration, quit <-chan struct{}, newRouterGeneratorFc RouterGeneratorFc) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			log.Println("periodic metadata refresh")
			newRouter, err := newRouterGeneratorFc()
			if err != nil {
				log.Println("failed preparing router, skipping swap", err)
				continue
			}
			rs.Swap(newRouter)
			log.Println("periodic metadata refresh finished")
		case <-quit:
			log.Println("quitting periodic refresh")
			return
		}
	}
}
