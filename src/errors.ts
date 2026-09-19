export class EcvError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** Ciphertext failed authentication: tampering, corruption or wrong key. */
export class IntegrityError extends EcvError {
  constructor(message: string) {
    super("INTEGRITY", message);
  }
}

export class AuthError extends EcvError {
  constructor(message: string) {
    super("AUTH", message);
  }
}

export class PathError extends EcvError {
  constructor(message: string) {
    super("PATH", message);
  }
}

export class PolicyError extends EcvError {
  constructor(message: string) {
    super("POLICY", message);
  }
}

export class SessionExpiredError extends EcvError {
  constructor(message = "session expired") {
    super("SESSION_EXPIRED", message);
  }
}

export class NotFoundError extends EcvError {
  constructor(message: string) {
    super("NOT_FOUND", message);
  }
}
