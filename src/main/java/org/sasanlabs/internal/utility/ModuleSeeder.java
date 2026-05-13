package org.sasanlabs.internal.utility;

import org.sasanlabs.configuration.DatabaseSeeder;

/**
 * Implement to seed the database for a module. ModuleSeeders are auto-discovered and called by
 * {@link DatabaseSeeder} on application startup.
 */
public interface ModuleSeeder {

    // Contains all inserts operations for data
    void seed();

    // Return true if module has already been seeded
    boolean isSeeded();
}
