package com.example.product.controller;

import com.example.product.model.Product;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final List<Product> products = new CopyOnWriteArrayList<>(List.of(
            new Product(1L, "Laptop Dell XPS 15", new BigDecimal("1500.00")),
            new Product(2L, "MacBook Pro M3", new BigDecimal("2000.00")),
            new Product(3L, "Keyboard Mech Keychron", new BigDecimal("120.00"))
    ));

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(new ArrayList<>(products));
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
