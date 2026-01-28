import { ObjectReference } from "../types/object-reference.js";
import {
  ObjectSpecifier,
  isElementSpecifier,
  isNamedSpecifier,
  isIdSpecifier,
  isPropertySpecifier,
  ElementSpecifier
} from "../types/object-specifier.js";
import { ReferenceStore } from "./reference-store.js";

/**
 * Executes queries against applications and manages object references.
 * Builds JXA code from ObjectSpecifier types and executes queries.
 */
export class QueryExecutor {
  constructor(
    private referenceStore: ReferenceStore
  ) {}

  /**
   * Query an object and return a reference.
   *
   * @param app - The application name (e.g., "Mail")
   * @param specifier - The object specifier to resolve
   * @returns A reference to the resolved object
   */
  async queryObject(
    app: string,
    specifier: ObjectSpecifier
  ): Promise<ObjectReference> {
    // 1. Build JXA code to resolve specifier
    const jxaCode = this.buildObjectPath(specifier, `Application("${app}")`);

    // 2. Execute JXA (for Phase 1, we mock this - will integrate actual execution in Task 5)
    // In production, this would call the JXA executor
    // const result = await this.jxaExecutor.execute(app, jxaCode);

    // 3. Extract object type from specifier
    const objectType = this.extractObjectType(specifier);

    // 4. Create reference in store
    const referenceId = this.referenceStore.create(app, objectType, specifier);

    // 5. Return reference
    const reference = this.referenceStore.get(referenceId);
    if (!reference) {
      throw new Error('Failed to create reference');
    }
    return reference;
  }

  /**
   * Get properties of a referenced object.
   *
   * @param referenceId - The ID of the reference
   * @param properties - Optional array of property names to retrieve
   * @returns Record of property names to values
   */
  async getProperties(
    referenceId: string,
    properties?: string[]
  ): Promise<Record<string, any>> {
    // 1. Get reference from store
    const reference = this.referenceStore.get(referenceId);
    if (!reference) {
      throw new Error(`Reference not found: ${referenceId}`);
    }

    // 2. Touch reference (update lastAccessedAt)
    this.referenceStore.touch(referenceId);

    // 3. Build JXA to get properties
    const objectPath = this.buildObjectPath(reference.specifier, `Application("${reference.app}")`);

    let jxaCode: string;
    if (properties && properties.length > 0) {
      // Get specific properties
      const propertyAccess = properties.map(prop =>
        `${this.camelCase(prop)}: obj.${this.camelCase(prop)}()`
      ).join(', ');
      jxaCode = `
        const app = Application("${reference.app}");
        const obj = ${objectPath};
        return { ${propertyAccess} };
      `;
    } else {
      // Get all properties (in production, would use properties())
      jxaCode = `
        const app = Application("${reference.app}");
        const obj = ${objectPath};
        return obj.properties();
      `;
    }

    // 4. Execute JXA (mocked for Phase 1)
    // In production: const result = await this.jxaExecutor.execute(reference.app, jxaCode);
    const mockResult: Record<string, any> = {};

    // 5. Parse and return properties
    return mockResult;
  }

  /**
   * Get elements from a container.
   *
   * @param container - Reference ID or ObjectSpecifier
   * @param elementType - Type of elements to retrieve
   * @param limit - Maximum number of elements to return (default: 100)
   * @returns Elements with metadata
   */
  async getElements(
    container: string | ObjectSpecifier,
    elementType: string,
    limit: number = 100
  ): Promise<{ elements: ObjectReference[]; count: number; hasMore: boolean }> {
    // 1. Resolve container (reference ID or specifier)
    let containerSpec: ObjectSpecifier;
    let app: string;

    if (typeof container === 'string') {
      // It's a reference ID
      const reference = this.referenceStore.get(container);
      if (!reference) {
        throw new Error(`Reference not found: ${container}`);
      }
      containerSpec = reference.specifier;
      app = reference.app;
    } else {
      // It's a specifier - need to infer app (for Phase 1, we'll assume Mail)
      containerSpec = container;
      app = 'Mail'; // TODO: Extract from context or require as parameter
    }

    // 2. Build JXA to get elements
    const containerPath = this.buildObjectPath(containerSpec, `Application("${app}")`);
    const elementsPath = `${containerPath}.${this.pluralize(elementType)}`;

    const jxaCode = `
      const app = Application("${app}");
      const container = ${containerPath};
      const elements = container.${this.pluralize(elementType)};
      return {
        count: elements.length,
        items: elements.slice(0, ${limit})
      };
    `;

    // 3. Execute JXA (mocked for Phase 1)
    // In production: const result = await this.jxaExecutor.execute(app, jxaCode);
    const mockResult = this.mockExecuteGetElements(app, containerSpec, elementType, limit);

    // 4. Create references for each element
    const elements: ObjectReference[] = mockResult.items.map((item: any, index: number) => {
      const elementSpec: ElementSpecifier = {
        type: 'element',
        element: elementType,
        index,
        container: containerSpec
      };

      const referenceId = this.referenceStore.create(app, elementType, elementSpec);
      const reference = this.referenceStore.get(referenceId);
      if (!reference) {
        throw new Error('Failed to create element reference');
      }
      return reference;
    });

    // 5. Return elements with metadata
    return {
      elements,
      count: mockResult.count,
      hasMore: mockResult.count > limit
    };
  }

  /**
   * Build JXA object path from specifier.
   * This generates the correct JXA syntax for accessing objects.
   *
   * @param specifier - The object specifier
   * @param appVar - The app variable name (default: "app")
   * @returns JXA path string
   */
  private buildObjectPath(specifier: ObjectSpecifier, appVar: string = "app"): string {
    if (isElementSpecifier(specifier)) {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.messages[0] or container.messages[index]
      return `${containerPath}.${this.pluralize(specifier.element)}[${specifier.index}]`;
    }

    if (isNamedSpecifier(specifier)) {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.mailboxes.byName("inbox")
      return `${containerPath}.${this.pluralize(specifier.element)}.byName("${specifier.name}")`;
    }

    if (isIdSpecifier(specifier)) {
      const containerPath = specifier.container === "application"
        ? appVar
        : this.buildObjectPath(specifier.container, appVar);
      // JXA: app.messages.byId("abc123")
      return `${containerPath}.${this.pluralize(specifier.element)}.byId("${specifier.id}")`;
    }

    if (isPropertySpecifier(specifier)) {
      // Handle "of" being either reference ID or specifier
      const ofPath = typeof specifier.of === "string"
        ? this.resolveReferenceToPath(specifier.of)
        : this.buildObjectPath(specifier.of, appVar);
      // JXA: message.subject() or object.property()
      return `${ofPath}.${this.camelCase(specifier.property)}()`;
    }

    throw new Error(`Unsupported specifier type: ${(specifier as any).type}`);
  }

  /**
   * Resolve a reference ID to a JXA path.
   *
   * @param referenceId - The reference ID
   * @returns JXA path string
   */
  private resolveReferenceToPath(referenceId: string): string {
    const ref = this.referenceStore.get(referenceId);
    if (!ref) {
      throw new Error(`Reference not found: ${referenceId}`);
    }
    return this.buildObjectPath(ref.specifier, `Application("${ref.app}")`);
  }

  /**
   * Extract the object type from a specifier.
   *
   * @param specifier - The object specifier
   * @returns The object type
   */
  private extractObjectType(specifier: ObjectSpecifier): string {
    if (isElementSpecifier(specifier)) return specifier.element;
    if (isNamedSpecifier(specifier)) return specifier.element;
    if (isIdSpecifier(specifier)) return specifier.element;
    if (isPropertySpecifier(specifier)) {
      // For properties, extract type from "of"
      if (typeof specifier.of === "string") {
        const ref = this.referenceStore.get(specifier.of);
        return ref?.type || "unknown";
      }
      return this.extractObjectType(specifier.of);
    }
    return "unknown";
  }

  /**
   * Convert a property name to camelCase for JXA.
   *
   * @param str - The property name (e.g., "read status")
   * @returns Camel-cased property name (e.g., "readStatus")
   */
  private camelCase(str: string): string {
    return str.replace(/\s+(\w)/g, (_, char) => char.toUpperCase());
  }

  /**
   * Pluralize an element name for JXA collection access.
   *
   * @param str - The element name (e.g., "message")
   * @returns Pluralized name (e.g., "messages")
   */
  private pluralize(str: string): string {
    if (str.endsWith("s") || str.endsWith("x")) return str + "es";
    return str + "s";
  }

  /**
   * Mock implementation of getElements JXA execution.
   * This is a protected method to allow testing subclasses to override.
   * In Phase 5, this will be replaced with actual JXA execution.
   *
   * @protected
   */
  protected mockExecuteGetElements(
    app: string,
    containerSpec: ObjectSpecifier,
    elementType: string,
    limit: number
  ): { count: number; items: any[] } {
    return {
      count: 0,
      items: []
    };
  }
}
