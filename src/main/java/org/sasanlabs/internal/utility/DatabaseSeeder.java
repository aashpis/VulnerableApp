package org.sasanlabs.internal.utility;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.List;
/**
 * Runs all {@link ModuleSeeder} implementations once the application is ready,
 * ensuring the database is populated before the app accepts requests.
 */
@Component
public class DatabaseSeeder {

    //  Finds every @Component that implements ModuleSeeder
    private final List<ModuleSeeder> seeders;

    public DatabaseSeeder(List<ModuleSeeder> seeders) {
        this.seeders = seeders;
    }


    @EventListener(ApplicationReadyEvent.class) // Runs before app can take requests
    public void seedAllModules() {
        System.out.println("Starting Global Database Seeding...");

        for (ModuleSeeder seeder : seeders) {
            if (!seeder.isSeeded()) {
                seeder.seed();
            }
        }

        System.out.println("Seeding complete. Processed " + seeders.size() + " modules.");
    }
}