/**
 * Virtual Scrolling Implementation
 * Renders only visible items for long lists (100+ items)
 */

// Prevent duplicate loading
if (window.virtualScrollLoaded) {
  console.log("⚡ Virtual scroll already loaded, skipping...");
} else {
  window.virtualScrollLoaded = true;

class VirtualScroll {
  constructor(container, items, renderItem, options = {}) {
    this.container = container;
    this.items = items;
    this.renderItem = renderItem;

    // Configuration
    this.itemHeight = options.itemHeight || 80; // Height of each item in px
    this.buffer = options.buffer || 5; // Extra items to render above/below viewport
    this.scrollThrottle = options.scrollThrottle || 16; // ~60fps

    // State
    this.startIndex = 0;
    this.endIndex = 0;
    this.visibleCount = 0;

    this.init();
  }

  init() {
    // Create virtual scroll container
    this.scrollContainer = document.createElement("div");
    this.scrollContainer.style.position = "relative";
    this.scrollContainer.style.overflow = "auto";
    this.scrollContainer.style.height = "100%";

    // Create spacer for total height
    this.spacer = document.createElement("div");
    this.spacer.style.height = `${this.items.length * this.itemHeight}px`;
    this.spacer.style.position = "relative";

    // Create viewport for visible items
    this.viewport = document.createElement("div");
    this.viewport.style.position = "absolute";
    this.viewport.style.top = "0";
    this.viewport.style.left = "0";
    this.viewport.style.right = "0";

    this.spacer.appendChild(this.viewport);
    this.scrollContainer.appendChild(this.spacer);
    this.container.appendChild(this.scrollContainer);

    // Bind scroll handler with throttling
    this.handleScroll = this.throttle(this.onScroll.bind(this), this.scrollThrottle);
    this.scrollContainer.addEventListener("scroll", this.handleScroll);

    // Initial render
    this.update();
  }

  onScroll() {
    this.update();
  }

  update() {
    const scrollTop = this.scrollContainer.scrollTop;
    const containerHeight = this.scrollContainer.clientHeight;

    // Calculate visible range
    this.startIndex = Math.floor(scrollTop / this.itemHeight);
    this.visibleCount = Math.ceil(containerHeight / this.itemHeight);
    this.endIndex = this.startIndex + this.visibleCount;

    // Add buffer
    this.startIndex = Math.max(0, this.startIndex - this.buffer);
    this.endIndex = Math.min(this.items.length, this.endIndex + this.buffer);

    // Render visible items
    this.render();
  }

  render() {
    // Clear viewport
    this.viewport.innerHTML = "";

    // Set viewport position
    this.viewport.style.transform = `translateY(${this.startIndex * this.itemHeight}px)`;

    // Render visible items
    for (let i = this.startIndex; i < this.endIndex; i++) {
      const item = this.items[i];
      const itemElement = this.renderItem(item, i);
      itemElement.style.height = `${this.itemHeight}px`;
      this.viewport.appendChild(itemElement);
    }
  }

  // Update items (when data changes)
  updateItems(newItems) {
    this.items = newItems;
    this.spacer.style.height = `${this.items.length * this.itemHeight}px`;
    this.update();
  }

  // Throttle helper
  throttle(func, limit) {
    let inThrottle;
    return function (...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => (inThrottle = false), limit);
      }
    };
  }

  // Destroy
  destroy() {
    this.scrollContainer.removeEventListener("scroll", this.handleScroll);
    this.container.innerHTML = "";
  }
}

// Auto-apply virtual scrolling to long lists
document.addEventListener("DOMContentLoaded", function () {
  // Look for lists with data-virtual-scroll attribute
  const virtualLists = document.querySelectorAll("[data-virtual-scroll]");

  virtualLists.forEach((list) => {
    const items = Array.from(list.children);
    if (items.length > 50) {
      // Only virtualize if more than 50 items
      const itemHeight = parseInt(list.getAttribute("data-item-height")) || 80;

      const renderItem = (item, index) => {
        return items[index].cloneNode(true);
      };

      new VirtualScroll(list, items, renderItem, { itemHeight });
      console.log(`✅ Virtual scroll enabled for list with ${items.length} items`);
    }
  });
});

// Export
window.VirtualScroll = VirtualScroll;
console.log("⚡ Virtual scroll utilities loaded");
} // End duplicate check
