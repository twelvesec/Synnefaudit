package com.twelvesec.cloudscan;

import org.reactivestreams.Publisher;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

public class PaginatorHelper {
    public static <T, R> CompletableFuture<List<R>> collectPaginatedItems(
        Publisher<T> publisher, 
        Function<T, List<R>> itemsExtractor) {
        
        CompletableFuture<List<R>> future = new CompletableFuture<>();
        List<R> items = new ArrayList<>();
        
        publisher.subscribe(new org.reactivestreams.Subscriber<T>() {
            @Override
            public void onSubscribe(org.reactivestreams.Subscription s) {
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(T page) {
                items.addAll(itemsExtractor.apply(page));
            }

            @Override
            public void onError(Throwable t) {
                future.completeExceptionally(t);
            }

            @Override
            public void onComplete() {
                future.complete(items);
            }
        });
        
        return future;
    }
}