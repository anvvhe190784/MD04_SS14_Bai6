package com.example.product.controller;

import com.example.product.model.Product;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final AtomicLong idGenerator = new AtomicLong(4L);

    private final List<Product> products = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "Laptop Dell XPS 15", new BigDecimal("1500.00")),
            new Product(2L, "MacBook Pro M3", new BigDecimal("2000.00")),
            new Product(3L, "Keyboard Mech Keychron", new BigDecimal("120.00"))
    ));

    @GetMapping
    @PreAuthorize("hasAuthority('PRODUCT_READ')")
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(new ArrayList<>(products));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('PRODUCT_CREATE')")
    public ResponseEntity<Product> createProduct(@RequestBody Product productRequest) {
        Product newProduct = new Product(idGenerator.getAndIncrement(), productRequest.name(), productRequest.price());
        products.add(newProduct);
        return ResponseEntity.status(HttpStatus.CREATED).body(newProduct);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        boolean removed = products.removeIf(p -> p.id().equals(id));
        if (removed) {
            return ResponseEntity.ok(Map.of("message", "Product deleted successfully", "id", id));
        }
        return ResponseEntity.ok(Map.of("message", "Product not found or already deleted", "id", id));
    }
}
