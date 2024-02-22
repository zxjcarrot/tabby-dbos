vmcache: vmcache.cpp tpcc/*pp
	g++ -O1 -DNDEBUG -std=c++20 -no-pie -mincoming-stack-boundary=3 -g -fnon-call-exceptions -fasynchronous-unwind-tables vmcache.cpp -o vmcache -laio -lpthread -ldl

tabby: tabby.cpp tpcc/*pp
	g++ -O1 -DNDEBUG -DENABLE_DUNE -std=c++20 -I../../libdune -no-pie -mincoming-stack-boundary=3 -g -fnon-call-exceptions -fasynchronous-unwind-tables tabby.cpp -o tabby -laio -L../../libdune -ldune -lbfd -ldl -lpthread

vmcache_test_dune: array_test.cpp
	g++ -DNDEBUG  -O3 -std=c++20  -I../../libdune -no-pie -mincoming-stack-boundary=3  -g -fnon-call-exceptions -fasynchronous-unwind-tables array_test.cpp -o array_test_dune -DENABLE_DUNE -L../../libdune -ldune 

vmcache_test: array_test.cpp
	g++ -DNDEBUG -O3 -std=c++20 -g -fnon-call-exceptions -fasynchronous-unwind-tables array_test.cpp -o array_test   -I../../libdune -no-pie -mincoming-stack-boundary=3 

clean:
	rm vmcache -f
	rm tabby -f