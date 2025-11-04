class TempStorage {
  constructor() {
    this.registrations = new Map();
    this.passwordRecovery = new Map();
  }

  saveRegistration(email, data) {
    this.registrations.set(email, {
      ...data,
      createdAt: Date.now()
    });
    this.cleanOldRegistrations();
  }

  getRegistration(email) {
    return this.registrations.get(email);
  }

  deleteRegistration(email) {
    this.registrations.delete(email);
  }

  saveRecovery(email, data) {
    this.passwordRecovery.set(email, {
      ...data,
      createdAt: Date.now()
    });
  }

  getRecovery(email) {
    return this.passwordRecovery.get(email);
  }

  deleteRecovery(email) {
    this.passwordRecovery.delete(email);
  }

  // Limpiar registros antiguos
  cleanOldRegistrations() {
    const TEN_MINUTES = 10 * 60 * 1000;
    const now = Date.now();

    for (const [email, data] of this.registrations.entries()) {
      if (now - data.createdAt > TEN_MINUTES) {
        this.registrations.delete(email);
      }
    }
  }
}

export const tempStorage = new TempStorage();